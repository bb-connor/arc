# Security roadmap execution and launch ledger

Historical evidence ledger. For current priorities, pending verification and
milestone state, use [launch status](launch-status.md) and the accepted
[execution plan](launch-execution-plan.md). Earlier running-process and active-goal
statements describe their original checkpoints, not current process state.

## Release contract

Deliver the existing protocol-primitives, active-defense, and enterprise-hardening
roadmap as one integrated candidate. Publish qualified Rust crates and a confined
Linux developer preview with automatic response disabled. Complete a separate
observed internal engineering pilot before promoting reversible containment.

The enforced native profile is one operator with authoritative durable state on
Linux x86_64, kernel 6.7 or newer, and every cage prerequisite verified. Portable
verification has its own platform evidence. Distributed-linearizable authority,
mobile hardware qualification, other native sandboxes, customer hosting, and
economic-product expansion are follow-up profiles, not preview claims.

The source contracts remain:

- [Protocol primitives](../superpowers/plans/2026-07-09-protocol-primitives.md)
- [Active defense](../superpowers/plans/2026-07-09-security-active-defense.md)
- [Enterprise hardening](../superpowers/plans/2026-07-09-enterprise-hardening.md)
- [Operational promotion](active-defense-rollout.md)

## Candidate and evidence rules

Integration starts from main `f5566d9a765c21cb36652a99c79de64968a656bf`
and includes security source `c85ef77b08ddcb52c9120f8b9a5c8b85532b98b4`.
The security source is a direct descendant of that main revision; all 50 commits
were fast-forwarded into the isolated `security/launch-integration` branch.
Existing working trees remain unchanged.

Evidence states are independent: implemented, locally verified, hosted-qualified,
and operationally qualified. A source change invalidates evidence for its affected
input closure. A passing metadata validator does not reproduce a mutation campaign.
Skipped platform probes do not qualify that platform. Report source SHA, command,
executed test inventory, artifacts, tool versions, and hosted run attempt together.

No row below claims hosted or operational qualification for the integrated source.

## Requirement ledger

`Present` means implementation was carried into the candidate and still needs
requirement-specific qualification. Task and phase references cover the complete
original plans; individual defects and evidence are recorded below this table.

| Arc / original requirement | Candidate state | Required evidence / remaining work |
| --- | --- | --- |
| Protocol 0: characterize existing authority | Present | Existing budget, approval, and receipt regressions |
| Protocol 1: signed aggregate root and negotiation | Present | Issuance, attenuation, root substitution, unsupported-feature rejection |
| Protocol 2: composite holds and durable stores | Present | Concurrent grant/family/broker admission, restart, atomic revocation/capture |
| Protocol 2: admission ordering and terminal projection | Present | Crash matrix and original operation identity across recovery |
| Protocol 2: original durable authority profile | Retained v4 pins explicit runtime, approval and DPoP selections; native selection requires retained admission; targeted kernel/runtime/SQLite/control-plane qualification complete | Remaining legacy-consumer and composed recovery qualification; no in-place authority upgrade, arbitrary legacy callback identity claim, or external dispatch authorization; see the original operation authority profile checkpoint below |
| Protocol 2: stable trusted security identity across durable replay | Ordinary/nested begin and pre-dispatch freeze, private caller decoding, retained v2 request data and owner-restart replay locally verified | Live flow observations and authority-specific native participant ownership remain separate; hook presence is not source identity or activation; see the stable security identity checkpoint below |
| Protocol 2: operation-owned runtime replay custody | Live ordinary/nested dispatch, grant fallback, nonce integration and explicit activation locally verified; composed three-resource ordinary lifecycle and controlled overlap exercised | Complete nested/combinatorial failure matrix, concurrent-process and process-crash qualification; operator quiescence before activation; see the live runtime admission and composed-custody checkpoints below |
| Protocol 2: operation-owned governed approval replay custody | Source activation, operation-fenced claims, exact release, expiry-aware budget/dispatch boundaries and kernel recovery implemented; configured normal/nested/preflight acquisition and legacy exclusion locally verified | Complete combined runtime/credential interruption and independent-process qualification; DPoP history remains a separate requirement |
| Protocol 2: DPoP replay continuity and custody | Instance-bound retirement, exact-source import, explicit signed v2 activation and physical SQLite custody locally verified; configured kernel normal/nested/preflight acquisition, exact cleanup, source-loss recovery and composed approval grant fallback locally verified | Authenticated deployment selection, full caller credential/security custody, complete composed interruption and independent-process qualification; lost inactive history must refuse or require an independently authenticated transition, never a fresh empty cache; see the configured DPoP kernel checkpoint below |
| Protocol 2: external caller dispatch commitment | Typed private return component retained at report-time capture; unsupported credential/security-hook caller profiles now reject before acquisition; handshake missing and contract counterexample remains | Complete durable typed admission snapshot including credential/security custody, authenticated start before the external effect, executor-owned durable claim and delivery evidence; lost report plus expiry must not refund an execution; see the caller dispatch design and live security-owner checkpoint below |
| Protocol 2: operation-owned flow/declassification/security custody | Origin-bound production preparation, final-release checkpoint, source retirement/archive, scoped native hydration, transaction-owned flow/use/outbox composition, actual leased native joins and egress acquire/commit, anchored mixed history, portable two-phase readback and original native-authority selection locally verified; kernel-owned affine egress coordinator, native post-join policy and production before-budget classified-input full-source join implemented; immutable preparation journal and dedicated atomic quota/dispatch-ledger capture with borrowed actual credential custody locally exercised | Native nonce/declassification custody and composed recovery, complete combined runtime/approval freshness and credential-failure matrix, complete authorization and frozen return-context coupling, post-commit acknowledgement/crash qualification, explicit destination activation, every affected legacy consumer, joined caller snapshot, current release policy and history-retention/scale qualification remain required; the capture-only checkpoint always stops before tool execution and does not release imported obligations |
| Protocol 2: operation-owned nonce participant | Integrated for in-kernel and remote strict dispatch with cumulative approval; durable caller-share ownership locally implemented | SQLite physical preflight ownership and reversal, write-ahead issuance, reservation, capture and commit, verified cancellation, retained history, signature profile isolation, kernel routing with startup recovery, loopback remote delivery with identity, pre-commit reachability, outcome-unknown terminals, cumulative approval under strict preflight, and process-kill cutpoints on the transport and inside finalization are implemented and exercised end to end; retirement of parked approval-required operations at startup and on an expired retry, and the sidecar's reservations as caller-executed durable operations, are implemented and exercised end to end; delegated caller-share settlement, restart, expiry, same-child ownership, ordinary-kernel exclusion, contention safety and tampering rejection now have production-store regressions; provider-signed delivery receipts and complete caller-share concurrency, recovery and release qualification remain open |
| Protocol 3: policy-owned threshold and signer set | Present | Exact action/capability/policy binding, duplicate signers, expiry |
| Protocol 3: durable replay, collection and federation compatibility | Partially integrated | Canonical collector, kernel-owned original cumulative-request context, native pending-proposal delivery and durable replay components are present; governed active-response sources, sidecar composition and durable session/nonce recovery remain open; preserved bilateral semantics still require qualification |
| Protocol 4: bounded runtime evidence | Present | Existing proof-parity and no-bypass contracts; no broader proof claim |
| Protocol 5: schemas, bindings, adapter preservation | Present | Registry, canonical vectors, four-language codegen and bridge parity |
| Protocol 6: conformance, concurrency, formal and release gates | Local integration advancing; hosted qualification pending | Draft PR #1117 remains blocked on its published head; local follow-up fixes are uncommitted and not covered by hosted CI; operator re-pins, dependency audits and exact-candidate reruns remain pending |
| Active defense 0: provenance and dependency direction | Present | Provenance and metadata dependency checks |
| Active defense 1: portable labels and lattice | Present | Property tests, positive/negative model checks, no_std/WASM build |
| Active defense 2: authenticated manifests and bridges | Present | Publisher cannot widen clearance; complete constructor/adapter inventory |
| Active defense 3: durable security stores | Present | Transactional transitions, isolation epochs, restart and outage tests |
| Active defense 4: flow and one-shot declassification | Present | Principal/lineage persistence, complete-source binding, egress fences |
| Active defense 5: kernel adapters and composition | Present | Every opted-in path installs complete authority or rejects |
| Active defense 6: private deception and tripwires | Present | Marker privacy, lifecycle recovery, deny before dispatch/delivery |
| Active defense 7: temporal correlation | Present | Trusted event provenance, bounded lateness, deterministic replay |
| Active defense 8: affected sets and approvals | Present | Exact lineage under issuance fences; action-bound approval |
| Active defense 8: effects and rollback | Present | Partial failure, overlapping restrictions, stale workers, truthful receipts |
| Active defense 9: scheduler and posture | Present | Durable leases, TTL ordering, restart, remaining contributions |
| Active defense 10: receipt and adversarial evidence | Present | Source-bound conformance and genuine caught mutants |
| Active defense 11: migration and promotion | Tools present; pilot pending | Verified backfill, observed shadow window, reviewed precision, signed stages |
| Enterprise 0: source and enforcement-stack audit | Present | Provenance, pinned dependencies, actual x86_64 Linux runner |
| Enterprise 1: RFC 6962 consistency | Present | Independent vectors and malformed-proof rejection |
| Enterprise 2-3: key log, witnessed rotation, verification | Present | Contiguous replay, strict-majority witnesses, fenced signing, rollback refusal |
| Enterprise 4-5: broker authorization, custody and execution | Present | No secret crossing, exact destination, shared quotas, durable reconciliation |
| Enterprise 6-8: retained resources, cage-init and supervision | Present | Actual Landlock/seccomp/exec probes, helper/FD/path mutation cases |
| Enterprise 9: production composition and receipts | Present in components | Integrated provider-backed invocation and failure/recovery evidence |
| Enterprise 10: schemas, adversarial evidence and migration | Pending qualification | Exact Linux capture, signed evidence, one-way migration, no fallback |
| Developer API and distribution | Pending | Packaged dependency closure and external Rust consumer |
| Confined reference runtime | Pending | Supervision, preflight, compiled tools, clean-machine installation |
| Observed internal pilot | Not started | Existing 14-day/100,000-invocation or 30-day window and finding review |

## Work sequence

1. Integrate, reconcile the historical security PR, diagnose baseline gate failures,
   and establish the complete candidate evidence inventory.
2. Close supported authority, flow, custody, confinement, and recovery seams with
   regression tests against the actual production boundaries.
3. Package the existing runtime and daemons with dedicated service identities,
   readiness checks, durable state, and a confined internal engineering swarm.
4. Qualify the Rust entrypoints `chio-kernel-core`, `chio-kernel`, and
   `chio-swarm-authority` and their production dependency closure outside the
   workspace. Use the next unused `0.2.0-alpha.N` package version independently
   of wire schema versions.
5. Publish the developer preview through the existing operator-controlled release
   mechanism after exact-candidate qualification. Automatic response stays off.
6. Run the observed internal pilot and the staged promotion contract. Retain real
   workload findings separately from injected attacks. Insufficient evidence
   leaves promotion pending; permanent revocation stays manual.

## Baseline findings

- Main CI run `33717023565` passed, but Release Qualification run `33717023364`
  failed on the same main SHA. The first failing gate reports duplicate function
  identity `validate_permissions` in the hosted-edge TLS source. Missing formal
  proof-report and web3 artifacts are downstream failures, not completed gates.
- The integrated threat ledger contains 20 partial rows. Its metadata checks
  passed on the original security source. Full threat closure is not claimed.
- The original security source passed 64 swarm-authority tests, 42 flow tests,
  and 16 response-authority tests. Two process helpers are intentionally ignored
  during ordinary enumeration and invoked by the process-boundary test.
- This development host is Linux aarch64. It cannot produce the required native
  x86_64 cage-enforcement release evidence.

## Integration closeout, 2026-09-04

Completed source changes in this integration worktree:

- Preserved hosted-edge TLS permission and file-identity behavior while giving
  each platform-specific helper one source-level function identity.
- Extended the structured adapter checker through literal `include!` source
  graphs, independent of filename extension. Exceptions retain physical file and
  function identity. Missing, cyclic, excessive-depth, dynamic, escaping, and
  symlinked includes reject. Test-only includes are excluded by attributes, not
  solely by their filenames. Arbitrary Rust macro expansion is not proved.
- Registered the exact MCP supervision threads without exempting side effects in
  their closures. Added native-launch contracts for manifest reauthorization,
  enterprise migration, and propagated authorization before direct spawn.
- Updated both evidence-container Cargo.lock pins to
  `2a66cf73b8fbc3bb740585ddb66bc96b24f71c4012b29681682f663261f6d928`.
  Relative to the previous pin's commit `c8c282427e`, the delta adds the internal
  response-authority and shared-IPC packages and updates workspace dependency
  edges. No third-party package version or checksum changes in that delta.
- Separated validated threshold records into `approval/collector.rs`, preserving
  the public `chio_kernel::approval` paths. Reduced `approval.rs` from 2,584 to
  1,763 lines. Added public API contract tests.
- Reproduced and fixed acceptance of a persisted satisfaction timestamp before
  receipt of a quorum. The validator now requires enough distinct, verified votes
  at the recorded time; later surplus votes remain valid.
- Separated control-plane diagnostic projection into `error.rs`, preserving
  `chio_control_plane::CliError`. The crate root is 937 lines; its obsolete
  size exception was removed, with no other caps increased or renewed.

Source checkpoints:

- `ccc11df414`: integrated release source checks, TLS helpers and evidence lock pin.
- `42cb55260d`: approval-record separation, causal validation and regression tests.
- `3c4e9a935c`: stable diagnostic projection separation and public API tests.

Local verification completed so far:

| Command / boundary | Result |
| --- | --- |
| `cargo test -p xtask --bin xtask adapter_no_bypass` | 19 passed, zero ignored |
| `cargo xtask check adapter-no-bypass` | Integrated production source contracts passed |
| `cargo test -p chio-finding-hosted-edge --lib tls::tests` | 7 passed, zero ignored |
| `cargo test -p chio-store-sqlite --test approval_store --test governed_approval_kernel_replay` | 8 passed, zero ignored |
| `cargo test -p chio-kernel --test threshold_approval_records` | 8 passed, zero ignored; causal timestamp regression failed before the fix |
| `cargo test -p chio-control-plane --test error_projection` | 2 passed, zero ignored |
| `cargo clippy -p xtask -p chio-kernel -p chio-control-plane -p chio-finding-hosted-edge --lib --bins -- -D warnings` | Passed |
| `cargo fmt --all -- --check` | Passed |
| Adapter wrapper and Rust file-hygiene self-tests | Passed; the full inherited hygiene inventory remains red |
| `cargo xtask gen proof-coverage --check` after regeneration | 58 rows and 166 artifacts match; no new proof campaign claimed |
| `python3 scripts/check-security-ci-contract.py` and its self-tests | Passed, including trust-boundary mutation rejection |
| Security and enterprise provenance, Linux dependency-stack inventory | Passed; inventory checks do not assert real kernel enforcement |
| `bash scripts/check-security-dependencies.sh` | Passed against resolved Cargo metadata |
| Rust public-surface policy | Passed; packages remain unpublished |

Open local closeout work:

- The inherited integration exceeded 26 Rust file-size caps. The two module
  separations above remove two violations. The remaining 24 need coherent
  decomposition and behavioral qualification; the full hygiene gate is still red.
- `ApprovalStore` exposes validated-record collector methods whose default
  implementations deny as unavailable. SQLite currently implements the distinct
  `ThresholdApprovalCollectorStore` API from `threshold_approval.rs`. The new record
  tests are not proof that these APIs are composed. Reconcile authority ownership,
  authenticated current-context loading, routes, persistence and callers before
  stabilizing or advertising durable collector coverage.
- Keep proof-coverage inventory synchronized as the remaining source layout is
  decomposed. The current inventory is refreshed; a new formal proof campaign
  remains separate work.
- Rerun all affected behavioral and full workspace gates, then obtain exact-head
  hosted qualification. No container image, native campaign, or pilot was launched
  by these local checks. Automatic response remains unpromoted.

## Collector recovery closeout, 2026-09-05

The HTTP collector uses `ThresholdApprovalCollectorStore`; the validated-record
methods on `ApprovalStore` remain separate and unavailable by default. This slice
hardens the active collector's recovery boundary without adding another store API
or claiming that the two paths are composed.

Completed source changes:

- Revalidate restored proposal signatures, algorithm metadata, current policy and
  trusted authority before returning, updating, delivering, or cancelling a
  proposal. Reconstruct the eligible-set requirement, check the policy timeout
  upper bound, and enforce the stored separation-of-duties rule.
- Verify every retained original token, including expired history, against its
  signed proposal. Reject duplicate IDs, digests and approvers, mismatched signed
  bindings, invalid quorum/state chronology and regressing update timestamps.
  Historical reads and replacement of an expired vote retain their existing
  behavior; delivery still requires a currently live quorum.
- Check fallible version increments before mutating the in-memory store.
- Read SQLite aggregate JSON, immutable proposal and requirement copies, indexed
  fields, and original vote rows in one transaction. Require agreement and valid
  vote receipt chronology before reads, creation retries or state changes.
- Serialize SQLite write transactions before reading their compare-and-swap
  inputs. Configure busy timeout and foreign-key enforcement on each borrowed
  connection. Concurrent identical creation retries remain idempotent; concurrent
  delivery transitions have one winner.
- Extract SQLite collector persistence and snapshot reconciliation into private
  modules. `approval_store.rs` is 1,537 lines, down from 1,848. Public Rust paths
  and wire formats are unchanged; no schema migration or larger file cap is used.

Regression evidence:

- Kernel recovery integration tests: 16 passed, zero ignored. The initial 11
  negative regressions failed before the fix, with the valid-delivery control
  passing. Additional tests cover signed-but-rebound votes, creation constraints,
  inconsistent quorum metadata, and historical expiry.
- SQLite recovery integration tests: 8 passed, zero ignored. Three initial
  negative tests failed before the fix. They exercise reopening the real store,
  index and vote-row corruption, unchanged state after rejection, and creation
  retry validation. Eight-thread creation and delivery races, transactional
  rollback on integer overflow, and canonical default-algorithm retries also pass.

Local compatibility checks, with `umask 022`:

| Command / boundary | Result |
| --- | --- |
| `cargo test -p chio-kernel -p chio-store-sqlite --test threshold_collector_recovery` | 24 passed, zero ignored |
| `cargo test -p chio-kernel --lib approval` | 44 passed, zero ignored, including the 4-test threshold subset |
| `cargo test -p chio-store-sqlite --lib approval_store` | 10 passed, zero ignored, including v1 migration and restart |
| `cargo test -p chio-kernel --test threshold_approval_records` | 8 passed, zero ignored; the separate validated-record API remains intact |
| `cargo test -p chio-store-sqlite --test approval_store --test governed_approval_kernel_replay` | 8 passed, zero ignored |
| `cargo test -p chio-http-core --test approvals_endpoints` | 11 passed, zero ignored |
| `cargo clippy -p chio-kernel -p chio-store-sqlite -p chio-http-core --lib --bins -- -D warnings` | Passed |
| `cargo clippy -p chio-kernel -p chio-store-sqlite --test threshold_collector_recovery -- -D warnings` | Passed |
| `cargo xtask check adapter-no-bypass` | Structured mediation contracts passed |
| `cargo xtask gen proof-coverage --check` after regeneration | 58 rows and 166 artifacts match; only inventory digests changed |
| Formatting, diff whitespace and Rust public-surface policy | Passed |
| Rust file-hygiene self-tests | Passed; full inventory still reports the 24 inherited violations |

This is snapshot integrity and current collector-authority validation, not
protection against an attacker replacing the entire database with a consistent
older snapshot. The collector still needs a trusted source of current request,
route, capability and policy context, a canonical validated-record persistence
path, and explicit lost-response/retry recovery before Task 9 can be closed.
The 24 inherited file-hygiene violations remain; this slice adds none. Full
workspace, exact-head hosted, native cage and observed-pilot qualification remain
separate requirements. Automatic response stays unpromoted.

## Canonical collector context and recovery, 2026-09-05

This slice reconciles the two collection APIs identified above. The existing
`ThresholdApprovalCollector` and `ThresholdApprovalCollectorStore` become the
canonical facade and persistence port. The unused default collection methods on
`ApprovalStore` are removed; its legacy human-approval and operation-owned replay
contracts remain. Existing validated registration/context types are reused, and
pure record projections remain available without owning a second storage path.

Completed source changes:

- Require `ThresholdApprovalContextResolver` at collector construction. Every
  facade operation resolves current authenticated request context and validates
  its exact route, requirement, subject, intent, capability digest, deadline,
  submitter and separation rule. A context constructor also rejects malformed
  deserialized routes and requirements.
- Accept only a signed proposal in the create HTTP body. Reject former
  caller-controlled authority fields even when their values are well-formed.
  Pass trusted current time through reads as well as mutations. API-protect
  rejects negative Unix timestamps before unsigned conversion.
- Require explicit trusted-source configuration for API-protect collection.
  The default sidecar does not enable collector endpoints from HTTP data.
- Advance approval-store schema metadata to revision 3. Retain unbound old
  collector records and reject their normal use until explicit
  `bind_existing_proposal` migration authenticates the original request.
  Atomic route binding preserves original votes, state and transition time.
  Retries do not increment its version again; overflow leaves storage unchanged.
- Make acknowledged creation and exact-vote retries return the actual retained
  state without resetting votes or receipt times. Reconstruct delivery retries
  from the immutable terminal timestamp, returning the exact original signed set
  only while all its members remain live. An expired surplus member cannot
  silently produce a smaller, differently hashed replay set.
- Enforce the execution replay identifier contract on restored votes, including
  the 512-byte ceiling and rejection of embedded NUL bytes.
- Preserve algorithm-aware submitter identities independently of replay token
  identifiers. A hybrid-key registration regression reproduced the incorrect
  application of the 512-byte token-ID limit to public-key encodings. Submitter
  encodings retain the collector artifact-size bound and exact comparison with
  authenticated typed context; replay token IDs keep their original limit.

The API and migration contract is documented in
[threshold approval collection](threshold-approval-collection.md). These are
intentional Rust and HTTP API changes, not a claim of wire compatibility with the
previous collector create request.

Targeted behavioral verification passed with `umask 022`: 135 tests, zero ignored.
The initial conformance build was interrupted to avoid exhausting the shared
build volume, then successfully rerun using an isolated temporary target cache.
The cache switch copied reusable artifacts without deleting the source cache or
modifying other worktrees.

| Command / boundary | Result |
| --- | --- |
| `cargo test -p chio-kernel --test threshold_approval_records` | 10 passed, including the reproduced hybrid-submitter regression |
| `cargo test -p chio-kernel -p chio-store-sqlite --test threshold_collector_recovery` | 36 passed: 25 kernel and 11 SQLite restart, corruption, retry and migration tests |
| `cargo test -p chio-conformance --test protocol_primitives_authority_bindings` | 3 passed, including mutation vectors and exact quorum |
| `cargo test -p chio-api-protect --lib approval` | 12 passed, including control access, clock rejection and absent-runtime denial |
| `cargo test -p chio-kernel --lib approval` | 44 passed, including cumulative and active-response admission/replay |
| `cargo test -p chio-store-sqlite --lib approval_store` | 10 passed, including migration and retained replay tombstones |
| `cargo test -p chio-http-core --test approvals_endpoints` | 12 passed, including rejection of well-formed caller-controlled authority fields |
| `cargo test -p chio-store-sqlite --test approval_store --test governed_approval_kernel_replay` | 8 passed, including execution replay denial after reopen |

Final local source checks also passed:

- Clippy with warnings denied for kernel, SQLite, HTTP-core and API-protect
  libraries/binaries, plus the kernel/SQLite recovery, validated-record, HTTP
  endpoint and conformance integration targets.
- Structured mediation contracts (`cargo xtask check adapter-no-bypass`).
- Formatting, diff whitespace, Rust public-surface policy and hygiene self-tests.
- Regenerated proof inventory and its check: 58 rows and 166 artifacts match.
  This establishes inventory consistency, not a formal proof campaign.

The full file-hygiene inventory continues to report the same 24 inherited
violations. No file caps were increased or renewed.

Remaining Task 9/runtime work is explicit: the mandatory resolver port is not a
production authenticated request source. The reference runtime still needs to
compose retained admission/request state, current capability and policy checks,
submitter authentication, collection and kernel execution replay into a tested
durable lifecycle. The default sidecar's mediated endpoint continues to reject
threshold input without its threshold policy resolver. Callback fixtures and
disabled endpoints do not close that requirement.

The next integration must establish these boundaries together:

- Capture request context only after authenticated kernel admission, retaining
  enough original authority material to recheck capability ancestry, revocation,
  policy and exact request bindings after restart. A collector snapshot or an
  unfenced raw operation read is not that source.
- Resolve request-ID ambiguity across subjects and operations fail-closed.
  Source separation rules from trusted policy/configuration and the submitter
  from authenticated request identity, not from a convenient proposal field.
- Test denied admission without context publication, restart with missing
  context, revocation and policy change after voting, then an admitted execution
  and lost-response retry against the same durable replay reservation. Collection
  must not become a second execution authorization path.

The shared-parser audit identified recursive parsing of the classical half of
hybrid key and signature strings before nested-hybrid rejection. That defect is
closed in the bounded-decoding section below. Collector artifact limits alone
did not qualify this lower-level input boundary.

Full workspace, exact-head hosted, real native confinement and observed-pilot
qualification remain open. No launch or promotion is authorized by these local
changes; automatic response stays unpromoted.

## Bounded cryptographic wire decoding

The shared parser now rejects nested hybrids through a finite, non-recursive
grammar. It checks envelope and component lengths before hex decoding. Fixed
seed, hash, key and signature components decode into arrays; ECDSA signature
vectors are bounded to the largest valid DER encoding. One private borrowed
string visitor serves key, signature and hash deserialization without requiring
an owned input copy. Valid canonical wire output is unchanged.

The initial regression run had seven failures and one passing positive control.
Four child-process controls reproduced stack-overflow termination through direct
key/signature parsing and JSON deserialization. Other controls reproduced nested
parsing before structural rejection, oversized ECDSA acceptance and decoding
before size checks. Two additional hash controls failed before the adjacent
hash-decoder and string-visitor fixes. The subprocess regressions now require
exactly one executed test as well as successful termination.

The `no_std` plus `pq` cross-build also exposed missing `alloc::format` and
`alloc::string::ToString` imports in the existing PQ module. Explicit imports
restore that portable feature combination without enabling `std`.

Local source verification uses Rust and Cargo 1.94.1 on aarch64 Linux, the
dedicated target directory, the workspace lockfile with offline resolution,
`umask 022` and disabled core dumps:

| Command / boundary | Result |
| --- | --- |
| `cargo test -p chio-core-types` | 560 passed, zero ignored |
| `cargo test -p chio-core-types --all-features` | 611 passed, zero ignored; includes real P-256, P-384 and all three hybrid families |
| Exact `Cryptographic wire bounds and real signatures` workflow step | 16 listed and executed tests match, zero ignored or filtered |
| `cargo test -p chio-core-types --no-default-features --features pq --test crypto_wire_bounds --test hybrid_bitflip` | 19 passed, zero ignored; includes real Ed25519 plus ML-DSA-65 verification |
| `cargo build -p chio-core-types --no-default-features --lib` | Native build passed |
| Same portable library build with `--target wasm32-unknown-unknown` | Passed without PQ and with `--features pq` |
| Kernel, SQLite and API-protect library tests filtered by `approval` | 90 passed: 44 kernel, 34 SQLite and 12 API-protect, zero ignored |
| Kernel/SQLite `threshold_approval_records`, `threshold_collector_recovery`, `approval_store`, `governed_approval_kernel_replay`, plus HTTP `approvals_endpoints` | 66 passed, zero ignored or filtered |
| `cargo clippy -p chio-core-types --all-features --lib --tests -- -D warnings` | Passed with no warning allowances added |

The default and all-feature counts overlap; they are separate feature profiles,
not an aggregate count of distinct tests. Cross-target builds do not establish
browser execution or native confinement. The existing FIPS smoke workflow now
runs the exact parser inventory and both portable build variants. Its name and
the crate's `fips` feature do not establish module validation or certification.

See [cryptographic wire decoding](crypto-wire-decoding.md) for the encoded-size
contract, retained raw-constructor semantics, and the boundary between parsing
and cryptographic verification. Enclosing transports still need body and read
limits; deserializer scratch buffers are outside this parser's allocation bound.

Source gates passed for formatting, diff whitespace, structured mediation
contracts, workflow lint, the security CI contract and its trust-boundary
mutation self-tests, the exact test inventory verifier's self-tests, and the
Rust public-surface policy and hygiene self-tests. Regenerated proof coverage
matches 58 rows and 166 artifacts,
including the new private parser modules. This is inventory consistency, not a
new formal proof campaign.

The same 24 inherited file-hygiene violations remain. No caps were raised or
renewed. Production threshold request-context composition, complete workspace and
exact-head hosted gates, real confinement and observed-pilot qualification remain
open. These changes do not authorize preview publication or response promotion.

## One threshold verifier and cryptographic floor

The admission-path audit reproduced seven failing regression cases and two
passing controls. Ordinary tool approvals had a duplicate verifier that did not
apply the kernel crypto floor or enforce algorithm metadata consistency. The
shared active-response verifier restricted vote algorithms but did not apply the
same restriction or metadata check to the signed proposal. Real hybrid capability
admission succeeded before mixed classical/hybrid threshold artifacts were
incorrectly accepted by the ordinary tool validator.

Both entrypoints now use the same pure verifier in
`threshold_approval/verification.rs`. The ordinary tool adapter resolves its
negotiated, current route policy exactly once and passes that requirement through
the crate-private entrypoint. The public facade retains its resolver contract.
The original public Rust paths remain re-exported; the public input field is
renamed from `allowed_token_algorithms` to `allowed_signing_algorithms` because it
governs the proposal and every vote. This is a Rust source migration, not a change
to signed wire bodies.

One kernel-floor mapping now serves threshold verification, active-response
submission proofs and authority attestations. Every proposal and vote must have
permitted, mutually consistent algorithm metadata, signing key and signature.
Absent metadata still means legacy Ed25519. A hybrid capability or hybrid votes
cannot elevate a classical proposal into the PQ-required profile. Empty
allowlists deny. Replay members are checked against the existing bounded ID
contract before a set is returned as verified.

The refactor preserves original signed artifacts, canonical approval-set hashes,
operation-owned replay projection and current capability admission. Active-response
submitter authentication and submitter/approver separation remain enforced by
their existing admission paths. The pure verifier does not mutate collector or
execution state. It is separate from the persistence facade; at this checkpoint
the threshold module root was 984 lines and the pure verification module was 259
lines.

The exact workflow inventory contains 20 regressions and controls, including real
Ed25519 and ML-DSA-65 hybrid signatures, mixed-artifact downgrade attempts,
metadata substitution, policy lookup counts, early token-set bounds, replay ID
bounds and canonical replay identity. The workflow has a separate kernel PQ job
and watches the kernel and core dependency paths. It does not silently accept an
empty or partially ignored filtered suite.

The first full PQ kernel run passed 1,149 tests and failed one diagnostic assertion:
a substituted plan binding was still denied, but its error wording had changed.
The shared verifier now retains the ordinary tool path's binding diagnostic.

Final local verification uses Rust/Cargo 1.94.1 on aarch64 Linux with offline
lockfile resolution, the dedicated target directory, `umask 022` and disabled
core dumps:

| Command / boundary | Result |
| --- | --- |
| Exact `Exact threshold crypto-floor regressions` workflow shell | 20 listed and executed tests match, zero ignored; other kernel tests explicitly filtered |
| `cargo test -p chio-kernel --features pq --lib` | 1,150 passed, zero ignored or filtered |
| `cargo test -p chio-kernel --lib` | 1,144 passed, zero ignored or filtered |
| Kernel/SQLite `threshold_approval_records`, `threshold_collector_recovery`, `approval_store`, `governed_approval_kernel_replay`, plus HTTP `approvals_endpoints` | 66 passed, zero ignored or filtered |
| SQLite and API-protect library tests filtered by `approval` | 46 passed: 34 SQLite and 12 API-protect, zero ignored |
| `cargo clippy -p chio-kernel --features pq --lib --tests -- -D warnings` | Passed without new warning allowances |

The default and PQ counts overlap and are not a combined count of distinct
tests. Formatting, diff whitespace, structured mediation contracts, workflow
lint, the security CI contract and its mutation self-tests, exact test-inventory
self-tests, and Rust public-surface policy and hygiene self-tests passed.
Regenerated proof coverage matches 58 rows and 166 artifacts, including the new
private verification module. This is inventory consistency, not a new formal
proof campaign. The same 24 inherited file-hygiene violations remain; no caps
were raised or renewed.

Production authenticated request-context composition remains open. Cumulative
proposal signing was still classical at this checkpoint; the next section records
boot-gated issuance integration. A complete PQ runtime still requires qualified
inline receipt composition rather than a weaker verifier.
Neither callback fixtures nor direct production-validator tests close these
runtime requirements. Complete workspace, hosted exact-head, native confinement,
package publication and observed-pilot qualification remain open. Automatic
response stays unpromoted.

## Boot-gated threshold proposal issuance

The next admission-path regression run reproduced two issuance failures: kernels
configured through the self-quote-gated hybrid backend still emitted classical
cumulative-approval proposals under both `AllowHybrid` and `PqRequired`. The
PQ-required control first admitted a real hybrid capability. A separate failing
control showed the raw PQ seed in `HybridSigningConfig` debug output. The classical
canonical-wire control passed before changes.

The existing boot helper now installs one shared, immutable proposal signer after
successful self-quote verification and backend construction. Its boxed return
type remains unchanged. The return handle forwards every signing entrypoint,
including atomic identity methods, without duplicating key material. Dropping the
handle leaves the installed signer live. A rejected quote or missing required
seed changes neither the previous signer nor the kernel floor. Debug output
redacts the seed.

The cumulative profile checks signer compatibility before reserving budget. It
uses the installed authority to issue a proposal and validates the result with
the same proposal-only verifier used by complete threshold-set verification.
Ed25519 retains its original canonical wire form; hybrid proposals carry the full
hybrid authority key and explicit algorithm. Trust in that key is limited to the
ordinary threshold proposal path, not automatically extended to capability
issuance or separately configured active-response authorities.

Pending replay revalidates retained proposal authority, membership, floor, exact
request bindings and expiry before resuming admission. The callback runs outside
the mutation sequencer, and later state changes remain operation-version and
store-fenced. Invalid retry attempts leave the original proposal and pending
allowance intact. They do not re-sign history, perform a second dispatch, or
claim a resource release. A restored compatible configuration can resume the same
operation. Directory membership, not an informational directory-version label,
determines the eligible-set digest.

The follow-up retry controls exposed that attempting ordinary pre-dispatch
compensation for a quiescent approval-required operation failed the release-proof
contract. Revalidation now rejects before that cleanup path. No release-proof
allowlist was widened, and these changes do not implement pending-operation
cancellation or qualify its complete expiry/recovery lifecycle.

Cumulative budget/proposal orchestration is now a separate 323-line module.
`kernel/validation.rs` decreased from 2,943 to 2,681 lines, bringing it below its
existing cap. Boot-gated proposal signing is isolated in a 180-line module. No
new crates, unsafe operations, unwrap/expect calls, or warning allowances were
added. The inherited file-hygiene failures decrease from 24 to 23, without raising
or renewing caps.

The exact issuance workflow inventory covers 17 tests. Its production-path
controls exercise pending issuance, approved dispatch, lost-response replay,
kernel reconstruction over retained fixture state, incompatible signer refusal,
changed authority/membership rejection, seed redaction and backend-method
forwarding. These fixtures do not establish physical process-crash or SQLite
restart qualification for the new signing composition.

Final local verification uses Rust/Cargo 1.94.1 on aarch64 Linux, offline
lockfile resolution, the dedicated target directory, `umask 022` and disabled
core dumps:

| Command / boundary | Result |
| --- | --- |
| Exact boot-gated threshold issuance workflow shell | 17 listed and executed tests match, zero ignored; other kernel tests explicitly filtered |
| Exact threshold crypto-floor workflow shell | 20 listed and executed tests match, zero ignored; other kernel tests explicitly filtered |
| `cargo test -p chio-kernel --features pq --lib` | 1,167 passed, zero ignored or filtered |
| `cargo test -p chio-kernel --lib` | 1,149 passed, zero ignored or filtered |
| Kernel `pq_key_load_after_self_quote` integration target with `pq` | Eight passed, zero ignored or filtered |
| Kernel/SQLite `threshold_approval_records`, `threshold_collector_recovery`, `approval_store`, `governed_approval_kernel_replay`, plus HTTP `approvals_endpoints` | 66 passed, zero ignored or filtered |
| SQLite and API-protect library tests filtered by `approval` | 46 passed: 34 SQLite and 12 API-protect, zero ignored |
| `cargo clippy -p chio-kernel --features pq --lib --tests -- -D warnings` | Passed without new warning allowances |

The default, PQ and exact-inventory counts overlap. Formatting, diff whitespace,
workflow lint, structured mediation contracts, the security CI contract and its
mutation self-tests, exact-inventory and runner self-tests, Rust public-surface
policy and its self-tests, and file-hygiene self-tests passed. The repository
file-hygiene check itself still reports the 23 inherited violations noted above.
Regenerated proof coverage matches 58 rows and 166 artifacts. This validates
inventory consistency, not a new formal proof campaign.

Production authenticated collector request context, complete pending-operation
cancellation/recovery, inline hybrid receipt composition, complete workspace and
hosted exact-head gates, native confinement, package publication and the observed
pilot remained open at this checkpoint. The inline receipt signer was still
classical; the next section records its integration. PQ proposal issuance alone
does not qualify a whole `PqRequired` runtime. Automatic response remains unpromoted.

## Shared boot authority across receipt paths

The receipt regression run reproduced three failures: ordinary inline and durable
dispatch receipts ignored the boot-selected hybrid key, and the signing queue
rejected a body naming that key. The classical inline/channel canonical-envelope
control passed after the fixture restored the original pre-binding signing nonce.
Re-signing a receipt's content-addressed ID as a new nonce is not byte-identity
evidence.

`KernelSigningAuthority` now owns one immutable backend and the floor under which
boot admitted it. Proposal issuance, ordinary inline receipts, the signing queue
and both bounded-memory fallback branches share that authority. Construction no
longer clones a fresh Ed25519 backend per ordinary receipt. The queue retains its
count and byte limits, lazy startup, shutdown state and content-preimage checks.
A failed boot reconfiguration leaves the previous authority and queue intact.
The backend forwarding contract still includes atomic identity signing methods.

Durable terminal qualification and replay use the actual receipt identity and
boot receipt floor. They retain all existing operation, output, decision,
metadata, tenant and replay bindings. Replay returns the original complete signed
envelope, not a newly signed equivalent. An incompatible authority cannot rewrite
history or dispatch the tool again. The finding-pool signer stays separately
pinned; a PQ-required boot rejects an incompatible classical pool signer instead
of silently substituting the ordinary kernel key.

`receipt_signing_public_key()` names the ordinary receipt authority.
`public_key()` retains its classical capability-authority meaning. The
capability-only floor setter does not replace receipt authority or its boot floor.
This separation is explicit in Rust documentation and regression coverage.

The broader default suite exposed a separate stale-clock failure in cumulative
issuance. Deterministic controls reproduced both erroneous rejection of a newly
created proposal and acceptance of an expired proposal under a stale admission
timestamp. The future-artifact rejection control passed unchanged. Proposal
validation now refreshes the existing trusted runtime clock after budget or
policy work; cumulative vote authorization refreshes it after proposal handling.
Artifact timestamps never advance it. No deadline tolerance or release-proof
allowance was added.

The receipt workflow checks 19 exact tests, including the `finding-market`
boundary. The proposal-issuance inventory contains 19 tests, including the three
clock controls. The existing backend-forwarding control moved with the shared
authority and has its own one-test exact gate. The prior 20 crypto-floor tests
remain separately enumerated. ML-DSA
signatures are randomized, so fresh inline and queued receipts are compared by
their canonical bodies and independent signature validity. Durable replay is
still compared byte-for-byte across the entire signed artifact.

Local verification uses Rust/Cargo 1.94.1 on aarch64 Linux with offline lockfile
resolution, the dedicated target directory, `umask 022` and disabled core dumps:

| Command / boundary | Result |
| --- | --- |
| Exact receipt, proposal-issuance, shared-forwarding and crypto-floor workflow shells | 19, 19, one and 20 listed/executed tests respectively; zero ignored, other kernel tests explicitly filtered |
| `cargo test -p chio-kernel --features pq --lib` | 1,189 passed, zero ignored or filtered |
| `cargo test -p chio-kernel --lib` | 1,155 passed, zero ignored or filtered |
| Kernel `hybrid_receipt_sign`, `receipt_signing_async`, `signer_crash`, `signing_queue_bound`, `signing_drop_counter`, `pq_key_load_after_self_quote` with `pq` | 34 passed, zero ignored or filtered |
| Kernel library `finding_pool::tests` with `pq,finding-market` | 29 passed, zero ignored; other kernel tests filtered |
| Kernel/SQLite approval records, recovery and replay, plus HTTP approval endpoints | 66 passed, zero ignored or filtered |
| SQLite and API-protect library tests filtered by `approval` | 46 passed, zero ignored; other library tests filtered |
| SQLite library `receipt_store`, single-threaded | 336 passed, two ignored, 788 filtered |
| `cargo clippy -p chio-kernel --features pq,finding-market --lib --tests -- -D warnings` | Passed without new warning allowances |

Default, PQ, feature-unified and exact-inventory counts overlap. The SQLite
ignored tests are `append_scale_proof_is_batch_bounded_across_history_sizes`
(release-mode million-receipt scale campaign) and
`prop_retention_preserves_append_invariant` (the source records a CI livelock).
Neither was executed or qualified by the receipt-store run. An initial
`finding_pool_tests` filter selected zero tests; the corrected `finding_pool::tests`
run above supplies the actual evidence. The exact inventory checker also refused
the moved forwarding test under the old proposal filter; its dedicated gate now
executes that control instead of deleting it from coverage.

Formatting, diff whitespace, workflow lint, Rust public-surface policy, the
security CI contract and its mutation self-tests, exact-inventory and runner
self-tests, and structured mediation contracts passed. Regenerated proof coverage
matches 58 rows and 166 artifacts. This is inventory consistency, not a new
formal proof campaign.

The same 23 inherited file-hygiene violations remain; no caps were raised or
renewed. `cargo xtask check formal-mirrors` reports seven inherited drift entries
across four files unchanged from this checkpoint's parent: async evaluation,
nested-flow evaluation, dispatch revalidation and response finalization. The
manifest is unchanged and no hashes were blessed. These are still release-gate
work, not a passing formal qualification claim.

See [kernel signing authority](kernel-signing-authority.md) for composition and
remaining boundaries. Production enterprise custody still requires
`KeyringSigningRouter` across all artifact-signing paths, shared epoch fencing,
durable artifact anchoring, witnessed rotation and qualified old-key history.
The boxed boot handle remains a compatibility API, not that custody boundary.
Capability issuance, child receipts, session anchors, execution nonces and
checkpoints remain separate authorities. These changes do not qualify an
all-artifact PQ runtime, physical process-crash recovery or production TEE
verification. Authenticated collector composition, pending cancellation/recovery,
full workspace and hosted gates, native confinement, packaging and observed pilot
remain open. Automatic response remains unpromoted.

## Sidecar control authentication

Tracing the authenticated collector boundary exposed a separate production
authorization gap: without a configured control token, the sidecar admitted
loopback callers to operator endpoints. Agents can share that interface. The
baseline regression run had seven passing controls and five failures: IPv4 and
IPv6 loopback access, sidecar-signed operator approval, capability revocation,
and duplicate Authorization headers when the first value was valid.

`proxy/control.rs` now owns one fail-closed credential gate for approval routes,
capability control, receipt submission, reconciliation and metrics. Missing or
blank configuration denies every caller. Exactly one valid bearer header is
required; duplicates deny in either order, including identical values. Token
comparison retains the constant-time primitive, and the response does not expose
credentials. Reconciliation uses this same gate. Peer and forwarded-address
metadata cannot authenticate a caller. Public health and independently authorized
data paths remain separate.

The compatibility change is intentional: local operator clients must configure
and present a control token. API-protect, CLI, Kubernetes-controller and Cloud Run
documentation now describe that contract. The token still grants broad
operator/tool-server access; it is not authenticated per-user submitter identity,
tenant isolation, scoped operator authorization, or enterprise request proof.

Local verification uses Rust/Cargo 1.94.1 on aarch64 Linux, offline lockfile
resolution, the dedicated target directory, `umask 022` and disabled core dumps:

- API-protect library: 191 passed, zero ignored or filtered. Existing authenticated
  approval, minting, revocation, receipt and reconciliation flows remain covered.
- Exact SDK Parity workflow shell: 12 listed/executed tests match, zero ignored;
  179 unrelated library tests are explicitly filtered. The route matrix covers
  18 endpoints plus unchanged approval/revocation state after denied mutations.
- API-protect Clippy, library and tests, with `-D warnings`: passed.
- Formatting, diff whitespace, workflow lint, Rust public-surface policy,
  structured mediation contracts and the security CI contract passed.
- Proof coverage was stale after adding the Rust source modules. Regeneration and its
  check now match 58 rows and 166 artifacts; this is not a new proof campaign.
- The documentation test target selected zero tests, so it supplies no executed
  API-example evidence. The controller change is flag-help text only; Go
  formatting is clean, but no new Go runtime qualification is claimed.

The exact and full test counts overlap. The new control module is 77 lines and
its focused tests and fixtures are 255 lines. Moving credential fixtures out of
the existing large test module keeps it below its unchanged cap. The same 23
inherited repository file-hygiene violations remain. No caps or warning allowances
were increased. Hosted execution of the added lane remains pending.

Production collector request context and end-to-end threshold recovery are still
open. At this checkpoint, generic upstream header forwarding still needed a
reserved-control credential containment check; the next section records that
implementation. Full workspace and hosted qualification, inherited formal drift,
native confinement, packaging and the observed pilot remain open. Automatic
response remains unpromoted.

## Reserved control credential containment

The live-upstream baseline reproduced six credential-forwarding failures, plus
missing header-work and configuration-validation bounds. Three compatibility
controls passed. Requests carrying the control token reached the upstream through
ordinary, duplicate, malformed, custom and non-UTF-8 header values, including an
unknown operator path falling through to the proxy.

The proxy now performs bounded byte-level containment before caller projection,
body reads, kernel admission and upstream dispatch. Every original header value
participates, including duplicates. It rejects the complete configured token
sequence even inside malformed or wrapped values. It does not silently strip a
credential and continue under a changed identity. Unrelated Bearer, Basic, Digest,
duplicate and binary headers remain preserved by the existing egress path.

A private borrowed credential view validates the shared authentication and
containment configuration. Nonempty tokens must fit the RFC 6750 token alphabet
and a local 512-byte maximum. Invalid configuration rejects before startup I/O.
The 64 KiB scan budget counts each header name and value, including duplicate
names. Equal-length candidate comparisons use the constant-time primitive,
accumulate every match and do not return early on matching prefixes. The check
does not allocate an input-sized buffer.

The focused suite contains 17 tests, including a real serving proxy that rejects
control headers while the client withholds its advertised body. Header byte-limit
and token-size controls exercise both inclusive bounds, duplicate accounting,
every-offset matches and same-length near misses. Socket bind failures fail the
new network tests rather than silently skipping them.

Local verification on aarch64 Linux with Rust/Cargo 1.94.1, offline lockfile
resolution, the dedicated target directory, `umask 022` and disabled core dumps:

- API-protect library: 208 passed, zero ignored or filtered.
- Exact SDK Parity workflow shells: 12 authentication and 17 containment tests
  each match their listed/executed inventories, zero ignored; other library
  tests are explicitly filtered.
- API-protect Clippy, library and tests, with `-D warnings`: passed.
- Structured mediation contracts: passed.
- Formatting, diff whitespace, workflow lint, Rust public-surface policy, the
  security CI contract and its mutation self-tests, exact-inventory and runner
  self-tests, and file-hygiene self-tests: passed.
- Regenerated proof coverage matches 58 rows and 166 artifacts. This is
  inventory consistency, not a new proof campaign.

The same 23 inherited repository file-hygiene violations remain; neither the new
module nor the updated large test module introduces a cap violation. No caps,
warning allowances or formal-mirror hashes were increased or blessed.

The complete and focused counts overlap. This closes the request-header
forwarding defect, not general secret detection in bodies, URLs, transformed
encodings or downstream-added credentials. It does not qualify throughput,
native confinement or hosted deployment. Production authenticated collector
context, end-to-end threshold recovery, the remaining workspace and formal
gates, packaging and the observed pilot remain open. Automatic response stays
unpromoted.

## Threshold session continuation

The authenticated-context investigation found that the control-plane policy
loader installs a real threshold requirement resolver with policy-pinned public
keys. It does not supply the collector's original authenticated request source.
The session path had an earlier integration failure: a cumulative approval wait
was recorded as terminal, and the approved retry failed with
`DuplicateRequestLineage`. A regression reproduced that failure before the fix.

The normalized session, blocking nested-flow and async nested-flow entrypoints
now retain an opaque continuation from the kernel's own persisted proposal
response. It binds the original proposal and immutable operation digests, with
exhaustive field handling and domain-separated canonical JSON. Request identity,
session anchor, parent and progress bindings must still match. Changed request
material or signed proposals cannot consume the wait. Current capability,
revocation, threshold policy and votes remain kernel execution checks.

The continuation claim uses the initial-admission lock order: lifecycle,
authentication, then request ownership. A production-lock regression reproduced
the check-to-claim window in the first implementation. Holding those authority
snapshots until the atomic claim closes that window; the locks are released
before kernel evaluation. A competing approved retry cannot claim the same wait.
The original lineage completes only after terminal evaluation.

Local verification used Rust 1.94.1 on aarch64 Linux, offline resolution, dedicated
target directories, `umask 022` and disabled core dumps:

- Kernel library: 1,171 default-profile tests and 1,205 PQ-profile tests passed,
  zero ignored or filtered. The profile counts overlap.
- Exact workflow shells: 34 boot/threshold-issuance tests and one session-ownership
  lock test matched their listed and executed inventories, zero ignored. These
  include the 15 new session-entrypoint tests and the production-lock regression.
- Threshold record and collector recovery integrations: 10 and 25 passed,
  respectively, zero ignored or filtered.
- Kernel Clippy for library and tests, default and PQ profiles, with `-D warnings`:
  passed.
- The existing real-session Loom admission/terminal test passed with 17 unrelated
  models filtered. Its build emitted three dead-code warnings for unchanged
  dispatch helpers. This verifies compatibility with that existing model, not a
  new Loom proof of threshold continuation.
- Structured mediation contracts, Rust public-surface policy, security CI
  contract, workflow lint, formatting and diff whitespace checks passed. Exact
  inventory/runner and file-hygiene self-tests passed.
- Regenerated proof coverage matches 58 rows and 166 artifacts. No new formal
  proof campaign is claimed.

The same 23 inherited file-hygiene violations and seven formal-mirror drifts
remain. The drift is confined to the same four unchanged Rust files. No caps,
warning allowances or formal-mirror hashes were increased or blessed.

This is live-session continuation, not authenticated collector context or durable
session recovery. The investigation also confirmed two separate remaining seams:
the CLI stdio response projection discards the pending proposal body, and durable
admission explicitly rejects every configured execution-nonce profile pending an
atomic nonce participant. The combined-profile probe reached that existing
restriction; its regression now asserts denial, not successful composition.
Cancellation, shutdown and dropped futures still need independent operation-owned
release/recovery evidence. A retained session digest cannot become a replacement
for the original authenticated request source.

Inspection also found that the CLI's `session/errors.rs` fallback ignored its
kernel argument and signed error receipts with a freshly generated key and an
`error` policy identity. The session report checkpoint below addresses that
adapter seam, distinguishing known rejection from an unknown execution outcome.

Full workspace and hosted qualification, native confinement, package closure and
the observed pilot remain open. Automatic response remains unpromoted.

## Kernel-owned session reports

The stdio baseline reproduced five failures and two passing compatibility
controls: conflict and evaluator-error receipts used independent keys, neither
path persisted its receipt, and an arbitrary evaluator failure was falsely
reported as a mediated denial.

The kernel now rejects conflicting approval shapes before session registration
or continuation ownership changes. All three session entrypoints share the wire
shape check and preserve the original approval wait. The stdio denial guard is
projected from the signed receipt.

Evaluator failures use a narrow kernel report factory. It signs and persists a
`trace_observation` with no decision and an explicit unknown execution outcome.
The verified observation is not proof of tool execution or absence of effects.
The report binds the original operation, context, capability and parameters;
policy identity and signing authority come from the kernel. Tenant identity is
an explicit authenticated snapshot, with no ambient fallback. Existing lineage
cannot be rebound into a different authentication epoch.

The factory neither copies caller financial metadata nor invokes settlement,
completes lineage, releases holds or authorizes execution retry. Missing required
persistence, dead writers, append failure and signing failure propagate. The CLI
drops the response if reporting itself fails, rather than substituting a key or
unaudited receipt. Its summaries count evaluation errors separately from denials.
See [session report receipts](session-report-receipts.md) for the full contract.

Local verification used Rust 1.94.1 on aarch64 Linux, offline dependency
resolution, `umask 022` and disabled core dumps:

| Check | Result |
| --- | --- |
| Kernel library, default profile | 1,185 passed, zero ignored or filtered |
| Kernel library, PQ profile | 1,221 passed, zero ignored or filtered |
| CLI session tests | 35 passed, zero ignored, 531 filtered |
| Core message tests | 14 passed, zero ignored, 372 filtered |
| `chio-core-types` and `chio-kernel-core`, `--no-default-features` | Both checks passed on this host |

Kernel Clippy for library and tests passed with `-D warnings` in default and PQ
profiles; CLI binary and tests also passed. Formatting, diff whitespace,
structured mediation, Rust public-surface policy, workflow lint, security CI
contracts and mutation self-tests, exact-inventory/runner self-tests and
file-hygiene self-tests passed. These do not replace the failing aggregate
hygiene and formal gates below or qualify the full portable platform matrix.

The exact local workflow replays passed: 16 session-report tests, 39 threshold
issuance tests, 20 boot-receipt tests and 10 stdio failure-receipt tests. Each
listed inventory matched execution, with zero ignored tests. The inventories
overlap. They include real SQLite shutdown/reopen, the three continuation
entrypoints, tenant rotation, settlement exclusion and recovery of a real durable
tool outcome after post-execution receipt-signing failure without redispatch.
This is local evidence, not a hosted CI qualification.

The broader CLI run was not green: 563 passed and three failed, zero ignored or
filtered. The failures are `isolated_test_cannot_read_operator_sibling_and_has_a_deadline`,
`isolated_test_supports_offline_path_vendored_rust` and
`sandbox_mounts_only_explicit_runtime_components` under the verified-fix tests.
All stop at `sandbox runtime tree exceeded its entry bound`. Their test and
production files are unchanged from this checkpoint's parent. The mount builder
scans the complete Rust sysroot against a 20,000-entry bound; this host's sysroot
contains 49,755 files, including 49,538 under `share`. Fixing the runtime input
closure requires a separate bounded implementation, not increasing the limit or
ignoring these tests.

The same 23 inherited file-hygiene violations and seven formal-mirror drifts
remain; no caps, warning allowances or mirror hashes were relaxed. Proof
coverage was regenerated and matches 58 rows and 166 artifacts. This does not
claim new formal proof coverage for the report factory.

Pending proposal delivery, original authenticated collector context, durable
session recovery and atomic execution-nonce composition remain open. Full
workspace and hosted qualification, native confinement, package closure and the
observed pilot remain open. Automatic response remains unpromoted.

## Explicit verified-fix Rust runtime inputs

The three CLI failures recorded above reproduced on the unchanged session-report
checkpoint. Rust discovery scanned installed documentation as runtime input and
exhausted its 20,000-entry bound before constructing a sandbox. The repair keeps
that bound and removes the whole-sysroot read-only mount.

Rust input selection now has a dedicated private module. It selects `cargo` and
`rustc`, optional `rustdoc`, Clippy and formatting tools, and individual files
under `lib/rustlib` for the installed targets. It never binds the sysroot root,
`bin` or `lib` directories wholesale. This distinction also matters when a
system-installed toolchain reports `/usr` as its sysroot. Documentation and
unrelated top-level tools and libraries are not selected.

ELF dependency sources are canonicalized and destination paths normalized.
Dependencies within the selected sysroot also receive relocated bindings to
preserve Rust's relative shared-library lookup. Native dependency bindings remain
available at their original layout. Only the staged Rust closure is relocated;
previously selected tools cannot be swept into it.

Missing required components, redirected rustlib roots, escaping component
symlinks, unresolved cycles, special files and oversized rustlib trees reject the
plan without publishing partial Rust mounts. Internal file aliases bind resolved
contents; internal directory aliases target the relocated sandbox path without
recursive traversal. No limit, ignored test or security gate was relaxed.

On Rust 1.94.1, aarch64 Linux, offline dependencies and `umask 022`, the complete
CLI binary unit suite passes: 575 tests, zero failed, ignored or filtered. This
includes nine new runtime selection regressions and all three previously failing
sandbox tests. The isolation tests reached real Git initialization and sandboxed
commands on this host, including offline path-vendored Rust compilation, sibling
file exclusion, bounded writes and command deadline enforcement. This is not a
full CLI integration-test or workspace qualification result.

CLI binary and test Clippy passes with `-D warnings`. The exact-inventory runner
also lists and executes all nine Rust runtime selection regressions, with zero
ignored tests and 566 intentionally filtered out. Formatting and diff whitespace
checks pass. Regenerated proof coverage matches 58 rows and 166 artifacts; this
does not assert new formal proof coverage for runtime discovery.

Structured mediation, Rust public-surface policy and their self-tests pass.
The security CI contract, its mutation self-tests and file-hygiene self-tests
pass. The same 23 inherited file-hygiene violations and seven formal-mirror drift
entries remain. The installed standalone
`actionlint` v1.7.7 also rejects existing workflow syntax and reports existing
shell diagnostics; this run does not claim an aggregate workflow-lint pass.
Workflow files and gate allowances are unchanged.

This is a path-based runtime selection repair, not immutable executable custody.
Runtime discovery still uses operator-installed tools and path-based mounts.
Descriptor-pinned inputs, bounded discovery subprocess capture and a complete
aggregate discovery deadline remain separate work. The existing Python and npm
tree discovery policies are unchanged. This checkpoint does not qualify an
arbitrary host toolchain or the native enforced launch profile.

## Native signed pending-approval delivery

The native stdio response now carries the kernel's complete signed threshold
proposal as `ToolCallResult::PendingApproval`. The previous adapter converted this
non-terminal wait to a policy error and discarded the proposal. A regression
against that unchanged adapter reproduced the lost `pending_approval` status
before the repair.

Projection validates the pending lifecycle and value shape before constructing
any frames. The request, proposal and signed receipt context must agree on the
original request ID. The canonical proposal bytes must survive typed decoding
unchanged and match the receipt content hash. Malformed or normalized artifacts,
streaming output and execution nonces reject projection without emitting chunks
or a substitute receipt. The adapter does not issue authority or replace the
kernel's signatures. Signature, policy and freshness verification remain duties
of the collector and execution-time kernel. Session accounting records approval
waits separately from both successful and denied execution.

Five new regressions exercise actual framed request/response transport and the
production session handler with SQLite admission and receipt persistence. They
verify proposal and receipt signatures, zero dispatch while waiting, approval of
the exact returned artifact, one dispatch on the original approved retry, and
preservation of the original wait after an altered retry is denied. Malformed
shape, request correlation, receipt binding, canonical encoding and execution
authority substitutions fail closed. A completed duplicate in the live session
is rejected without redispatch and produces the existing signed failure
observation. This is not durable terminal-result replay or restart recovery.

The wire schema defines the closed pending result and forbids an execution nonce
on its response frame. The Rust result enum rejects unknown fields consistently
with the existing closed result schemas. Existing result encodings are unchanged;
older peers must reject an unknown status. All four language bindings are
regenerated from 139 schemas, including 152 generated Python files. Shared
fixtures cover the result and malformed variants; three new Rust schema tests
also cover frame composition. Binding parsing is not cryptographic authority
verification, and these results do not claim every generated language enforces
every cross-field frame invariant.

Exercising the Python SDK exposed two existing import failures. Generated path
and environment root models instantiated constrained types before their Python
regex-engine configuration existed. A shape-checked generator transformation
now defers construction while retaining each root field, regex and configuration
unchanged. Two generator tests and six Python parameterized cases verify that
repair and retain canonical-path and loader/credential exclusions. The public
`MonetaryAmount` alias now imports the capability-domain model directly rather
than relying on an ambiguous generated root namespace. The TypeScript fixture
test also uses the actual generated capability type and the named Ajv export.

The complete CLI binary unit suite passes with 580 tests, and the complete Python
SDK suite passes with 176. The kernel library suite passes with 1,185 tests, and
all eight wire-schema tests pass. The combined core-types/conformance library
run passes with 408 and 39 tests respectively. The workflow's exact-inventory gates list and
execute the five delivery and three schema regressions with zero ignored tests.
The Go package tests, TypeScript shared-fixture test and explicit TypeScript
typecheck pass. All four code-generation checks pass. The core-types and
kernel-core no-default-features checks and core-types library/test Clippy pass.
CLI binary/test and generator Clippy pass with `-D warnings`. Formatting,
whitespace, Rust public-surface, security CI contract and the changed workflow's
standalone actionlint checks pass. Regenerated proof coverage matches 58 rows and
166 artifacts; it does not claim new formal proofs for response projection.
These are local results on Rust 1.94.1 and aarch64 Linux with offline dependencies
and permission-safe `umask 022`, not hosted or full-workspace qualification.

The original authenticated request source for collector activation, durable
session recovery, atomic execution-nonce composition, cancellation/shutdown
ownership and signing-key custody remain open. The 23 inherited hygiene
violations and seven formal-mirror drifts remain; no gate allowances or mirror
hashes were relaxed. Native enforced qualification, packaged dependency closure,
publication and the observed pilot remain open. Automatic response stays off.

## Evaluation-owned receipt context

Tracing the collector's authenticated-request source exposed a receipt isolation
defect on `16452727bbe2a95f19129d1937898c9f1e044e2b`. A deterministic regression
interleaved two real tool evaluations with the same correlation ID on a
current-thread runtime. The anonymous call completed while an authenticated
tenant's call was suspended. Its signed allow receipt incorrectly carried the
other call's tenant ID. Existing evaluation-keyed maps isolated nonempty tenant
values, but an absent value fell back to thread-local context held across await.

Async evaluation now owns both its unique evaluation key and its receipt context
through one private scope constructor. Ordinary and nested-flow entrypoints use
the same constructor. Tenant and admission-time federation snapshots remain
kernel-derived; a fresh evaluation starts with neither value, and that absence
suppresses ambient thread state. Synchronous callers retain their existing
thread-local fallback outside an async evaluation.

Scope guards retain their original shared context. Completion, future migration
and cancellation restore that context, not whichever evaluation or executor
thread happens to be active at drop time. Snapshot replacement uses the existing
`arc-swap` dependency. No public authority API, serialization format, new
dependency or unsafe code is introduced. The scope constructor returns the
task-local future directly instead of adding another async state-machine layer.

Six regressions cover the reproduced ordinary-path leak, the nested-path
equivalent, explicit empty scopes and nested restoration, movement between two
OS threads on completion and cancellation, dropping a suspended evaluation
inside another evaluation, and cleanup after cancelling a real session
evaluation at its tool boundary. The concurrent production cases verify signed
receipts and separate anonymous versus authenticated tenant attribution. The
workflow lists and executes the exact regression inventory with PQ enabled.
The large concurrent test futures are boxed; no thread-stack allowance is raised.

The complete default kernel library suite passes with 1,191 tests. The final
PQ-enabled kernel test binary produced by the workflow replay also passes its
complete 1,227-test inventory. The complete CLI binary unit suite passes with
580 tests. These full suites have zero failed, ignored or filtered tests. The
exact workflow replay lists and executes all six isolation regressions, with
zero ignored tests and 1,221 intentionally filtered out. Kernel library/test and
CLI binary/test Clippy pass with `-D warnings`.

Formatting, diff whitespace, structured mediation, Rust public-surface policy,
security CI contract and the changed workflow's standalone actionlint checks
pass. Security CI mutation self-tests and the public-surface and hygiene
self-tests pass. Regenerated proof coverage matches 58 rows and 166 artifacts;
no new formal proof coverage is claimed. The same 23 files remain over hygiene
limits, and seven tracked formal-mirror entries remain drifted. The two affected
evaluation modules are smaller after scope construction was consolidated. No
caps, gate allowances or formal-mirror hashes were relaxed.

These are local Rust 1.94.1/aarch64 Linux results with offline dependencies and
`umask 022`, not full-workspace, hosted, native-enforced or release qualification.

This repairs receipt-context custody, not authenticated collector activation or
complete cancellation semantics. The collector still needs original retained
request material, fenced storage provenance, current capability ancestry and
revocation checks, trusted policy and submitter identity, and ambiguity rejection
after restart. Neither a signed proposal, a receipt, a collector snapshot nor a
retry digest supplies that authority by itself. Durable session recovery,
execution-nonce composition and operation ownership remain separate open work.

## Atomic original tool request retention

Cumulative tool admission now writes a bounded original-request artifact in the
same SQLite transaction as its version-one operation and begin commit. The
artifact retains the complete signed capability, exact immutable request fields,
matching-grant indices and frozen post-return plan. The established v1 request
hash remains unchanged and is shared by admission and restored-record validation.
The begin participant digest binds the artifact's canonical bytes to the existing
fenced, anchored commit chain.

Reads return the operation and original material from one current-owner-fenced,
trusted-time-checked snapshot. Missing committed material, altered bytes, wrong
operation bindings, stale fences and regressed time fail closed. Exact replay
compares the original bytes and never backfills missing evidence. SQLite schema
v10 preserves legacy commits while adding immutable storage. Legacy cumulative
operations without originals cannot resume through inferred request backfill.

The retained artifact omits one-shot credentials and approval artifacts. Its
256 KiB bound applies before decoding stored bytes into Rust, with a SQLite
length check before BLOB allocation. Typed canonical re-encoding rejects unknown
nested fields and noncanonical representations. Diagnostic output excludes
capabilities and arguments. The test operation-store implementation was extracted
into a focused module instead of increasing its existing file cap.

That checkpoint closed durable retention, not authenticated collection. Capture occurs
after capability, revocation, subject, route and applicable DPoP prechecks but
before the remaining governed-input, guard and budget decisions. Raw retained
material for a prepared or denied operation cannot qualify collection. The
production resolver still needed to compose eligible operation state, unambiguous
request selection, current capability ancestry and revocation, policy and exact
intent checks, authenticated submitter identity and trusted separation rules.
No collector endpoint was enabled. Durable session recovery, atomic execution
nonces, operation ownership, witnessed key custody and the complete
collection-to-execution restart/replay lifecycle remained open at that checkpoint.
The kernel-owned resolver milestone below advances that source and lifecycle.

Local verification passed with `umask 022`:

| Boundary | Result |
| --- | --- |
| Full default kernel library | 1,194 passed, zero failed or ignored |
| Full PQ kernel library | 1,230 passed, zero failed or ignored |
| Final SQLite library test binary, run from its crate directory | 1,131 passed, zero failed, three existing ignored |
| Full CLI binary suite, including framed pending approval | 580 passed, zero failed or ignored |
| Actual workflow step: boot-gated threshold issuance with PQ | 42 exact tests passed, zero ignored |
| Actual workflow step: durable original request retention | Eight exact tests passed, zero ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |

The SQLite binary was rebuilt by the exact workflow step before its full run.
Its ignored cases are the million-receipt scale proof, the retention property
test quarantined under issue #1045, and the subprocess-only serving-owner helper.
The helper did run successfully through its parent test. No ignored result is
counted as proof of the corresponding scale or retention property.

Formatting, diff whitespace, changed-workflow actionlint, adapter mediation,
public-surface policy and self-tests, security CI contracts and mutation tests,
and file-hygiene self-tests passed. Proof inventory regeneration and check agree
on 58 rows and 166 artifacts. Full file hygiene still reports the same 23
inherited failing files, and formal mirror checking still reports the same seven
inherited drift entries. No caps or proof hashes were blessed. Full workspace,
exact-head hosted, native confinement, package and observed-pilot qualification
remain open. No publication, deployment or automatic-response promotion occurred.

## Kernel-owned collection authority and SQLite restart lifecycle

The Rust kernel now provides a collector factory backed by its retained original
cumulative tool admission. Construction requires completed durable startup
reconciliation and operator-owned separation rules bound to the active policy
hash. The resolver accepts only a unique `ApprovalRequired` operation, revalidates
its full capability and ancestry, current revocation and delegation views,
subject, route, grants, post-return plan, governed intent and threshold policy,
then rechecks the fenced original source after authority resolution.

The original capability-bound agent is the submitter. Applicable DPoP was checked
at original admission. This does not establish a separate human submitter or
physical-person identity. Collector HTTP fields, proposal bodies and restored
collector records remain insufficient sources of authority.

SQLite admission schema v11 adds an indexed request-ID lookup capped at two
results. Ambiguity includes other namespaces, operation kinds, terminal states
and legacy operations with no retained material. Migration preserves v10 request
bytes and operation commits. Missing implementations of the new store port fail
closed rather than selecting an arbitrary operation.

The real SQLite collection-to-execution restart test exposed a stale-owner bug:
cumulative approval resumption copied mutation authority from the historical
budget hold. The current serving owner correctly rejected it. Resumption now
obtains current fenced authority while the store independently verifies the
hold's historical owner and immutable admission binding. The test retains votes
through reopen, executes the original request once, replays the same receipt
after a lost response, reopens again and confirms no second tool invocation.

This advances the original-request source for cumulative tool calls, not the
whole threshold roadmap. Governed active-response original sources, sidecar
composition, process-crash cutpoints, durable session recovery, atomic execution
nonces, pending-operation cancellation and operation ownership remain open.
The diagnostic stale-owner path also showed that attempted compensation of a
quiescent approval-required operation is rejected; this change does not claim
that cancellation or compensation path is implemented. Witnessed key custody,
native confinement, exact-head hosted checks, package qualification and the
observed pilot remain separate gates. No HTTP endpoint, deployment, publication or
automatic-response promotion was enabled.

Local verification for this milestone uses `umask 022`. Both targeted workflow steps
were executed from the actual YAML run blocks, including exact inventory checks:

| Boundary | Result |
| --- | --- |
| Full default kernel library | 1,194 passed, zero failed or ignored |
| Full SQLite library test binary, run from its crate directory | 1,133 passed, zero failed, three existing ignored |
| Actual workflow step: durable original request retention and lookup | 10 exact tests passed, zero ignored |
| Actual workflow step: kernel collector restart lifecycle | Nine exact tests passed, zero ignored |
| Full PQ kernel library | 1,230 passed, zero failed or ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |
| Full CLI binary suite | 580 passed, zero failed or ignored |

The SQLite full run used eight test threads and completed in 302.98 seconds. Its
three ignored entries are unchanged: million-receipt scale proof, the retention
property test quarantined under issue #1045, and the subprocess-only owner helper.
The parent test executed the owner helper successfully. Ignored entries are not
qualification of their unexecuted scale or property claims.

Formatting, diff whitespace, changed-workflow actionlint, adapter mediation,
public-surface policy and self-tests, security CI contracts and mutation tests,
and file-hygiene self-tests passed. Proof inventory regeneration and check agree
on 58 rows and 166 artifacts. Full file hygiene still reports the same 23
inherited failing files; formal mirror checking still reports the same seven
inherited drift entries. No cap or proof hash was blessed. Full workspace and
release qualification remain open.

## Validated nonce boundary and kernel module separation

The kernel's execution-nonce configuration, issuance and request validation now
live in a dedicated `kernel/nonce_admission.rs` module. Public method signatures
and signed wire payloads are unchanged. Required-nonce and owned-credential paths
share one non-consuming request validator instead of maintaining duplicate
schema, expiry, signature and request-binding checks.

Successful validation returns a private `ValidatedExecutionNonce` borrowing the
immutable signed artifact. The internal consumption function accepts this proof
instead of raw signed data and rechecks expiry at consumption. The kernel's
reservation helper independently validates the exact request, including strict
mode's missing-nonce rule, even when a caller has already performed validation.
This removes an internal ordering assumption; it is not a claim that an external
dispatch bypass was demonstrated.

The proof has no public constructor or deserializer, and its debug output omits
the artifact. It establishes only the checked schema, expiry, signing key and exact
request binding. It is not a store reservation, replay verdict, current capability
authorization or durable admission-operation authority. The public legacy
`consume_execution_nonce` store port remains unchanged and remains a trusted
low-level API.

Five new tests cover all six request-binding fields, signature rejection at the
kernel request gates, non-consuming validation and opaque debug output,
strict-mode omission, and unsupported schemas. The workflow checks their exact
inventory and the existing expiry-at-consumption regression; ignored or missing
tests cannot satisfy these checks.

This is preparation for the atomic durable participant, not its implementation.
Durable admission still rejects every configured execution-nonce profile. The
legacy rollback path deletes its owned replay marker and cannot provide the
required operation-owned cancelled tombstone. Durable reservation with `Ready`,
commit with capture, pre-dispatch cancellation, restart reconciliation and the
strict preflight/execution identity model still need a shared atomic design and
crash-cutpoint qualification. No nonce-enabled sidecar profile, automatic response
or release promotion was enabled.

The separation reduces `construction.rs` from 2,092 to 1,886 lines, below the
ordinary 2,000-line production limit. Its obsolete size exception was removed.
The full hygiene gate now reports 22 inherited failing files, down from 23;
no cap was raised. Formal mirror checking still reports the same seven inherited
drift entries, with no proof hashes blessed. Full workspace, exact-head hosted,
native, package and observed-pilot qualification remain open.

Local verification uses Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
and `umask 022`. The new workflow step was executed from its actual YAML run block.

| Boundary | Result |
| --- | --- |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Full PQ kernel library | 1,235 passed, zero failed or ignored |
| Actual workflow: nonce validation and consumption | Five exact tests plus one exact expiry regression passed, zero ignored |
| SQLite execution-nonce store integration | Eight passed, zero failed or ignored |
| Kernel collector SQLite restart integration | Nine passed, zero failed or ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |
| Full CLI binary suite | 580 passed, zero failed or ignored |

SQLite evidence for this milestone is the two integration suites above, not a
new full SQLite-library run.

Formatting, diff whitespace, changed-workflow actionlint, adapter mediation,
public-surface policy and self-tests, security CI contracts and mutation tests,
and file-hygiene self-tests passed. Proof inventory regeneration and check agree
on 58 rows and 166 artifacts. These checks do not qualify the atomic durable nonce
profile or replace the remaining full-workspace and release gates.

## Atomic durable nonce reservation foundation

Admission schema v12 now stores a permanent operation-owned nonce reservation and
the exact `ReadyToDispatch` snapshot in the same transaction as that state change.
The reservation is unique both by operation and by nonce ID across coordinator
namespaces. Its canonical artifact, snapshot and reservation time are bound into
the existing admission commit chain and serving-owner anchor. Neither a nonce ID
attachment nor a matching caller-built snapshot substitutes for that evidence.

`AdmissionExecutionNonceReservationV1` verifies bounded canonical material,
signature, issuance interval, exact original request/capability/action binding
and any signed reserved-hold reference. Its trust-key argument is operator-owned,
not a wire field. The SQLite port additionally pins that issuer to the qualified
kernel coordinator lease, reads the retained original request under the current
fence, and rechecks current expiry before either reservation or idempotent replay.
Construction does not establish current capability authorization, store provenance
or permission to dispatch. Debug output omits the artifact.

The same fenced lookup and startup invariant checks verify reservation history.
SQLite checks encoded lengths before allocating untrusted values into Rust.
Expiration does not delete history or make its signed material fresh again.
The row is immutable and non-deletable; migration preserves existing original
request bytes and operation commits without inventing nonce reservations.

Ordinary compare-and-swap cannot attach a nonce ID, manufacture readiness or
advance a reserved operation. Capture and terminal projection paths reject nonce
operations until their atomic disposition participant is implemented. The kernel
still rejects every configured durable nonce profile. This milestone implements
reservation, lookup and integrity, not the committed/cancelled lifecycle or a
nonce-enabled runtime profile.

The next nonce work remains operation-owned commit with capture, cancellation
with verified pre-dispatch compensation, durable issuance and cross-profile
replay composition, strict preflight/execution identity, and recovery ownership.
The legacy replay cache remains separate and unchanged; its deletion-based
rollback cannot stand in for the required cancelled tombstone. Store-level tests
of ordered operation states do not qualify real budget capture, session recovery,
process-crash cutpoints or tool dispatch. The kernel-owned collector still covers
cumulative tool sources, not governed active-response sources or sidecar activation.

Ten reservation regressions cover atomic state/record writes, idempotent replay,
reopen under the new owner fence, three injected SQL mutation failures, forbidden
generic transitions, coordinator-key substitution, expiry, corruption/removal,
bounded restoration, permanent identity, historical-only expiry lookup, v11
migration and concurrent contenders in distinct namespaces. The exact workflow
inventory includes all ten with no ignored tests. The complete original roadmap
and release gates remain in force; no publication, deployment or automatic
response was enabled.

Local verification uses Rust 1.94.1 on Linux aarch64, offline Cargo resolution
and `umask 022`. The new exact-inventory step was run from the actual workflow YAML.

| Boundary | Result |
| --- | --- |
| Actual workflow: durable nonce reservation | Ten exact tests passed, zero ignored |
| Full SQLite library, eight test threads | 1,143 passed, zero failed, three existing ignored |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Full PQ kernel library | 1,235 passed, zero failed or ignored |
| Full CLI binary suite | 580 passed, zero failed or ignored |
| Legacy SQLite nonce-store integration | Eight passed, zero failed or ignored |
| Kernel collector SQLite restart integration | Nine passed, zero failed or ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |

The SQLite full run completed in 291.37 seconds. The ignored entries remain the
receipt-retention property test quarantined under issue #1045, the large-history
receipt scale proof, and the subprocess-only owner helper. The parent test ran
that helper successfully. No ignored entry is evidence for an unexecuted property
or scale claim.

Formatting, diff whitespace, changed-workflow actionlint, adapter mediation,
public-surface policy and self-tests, security CI contracts and mutation tests,
and file-hygiene self-tests passed. Proof inventory regeneration and check agree
on 58 rows and 166 artifacts. Full file hygiene still reports 22 inherited
failing files; formal mirror checking still reports seven inherited drift entries.
No cap or proof hash was blessed. Full workspace, exact-head hosted, native,
package and observed-pilot qualification remain open.

## Threshold reservation composition and retry qualification

The specialized threshold reservation transaction now accepts exactly its
proposal-hash and approval-set-hash attachments. It cannot attach a nonce or
another participant's authorization while reserving approvals. It also applies
the nonce transition qualifier alongside the existing channel qualifier. The
kernel caller already emits this exact two-attachment command; no public port or
persisted schema changed.

The initial regression run reproduced five failures: an extra nonce attachment,
a substituted signed packet on retry, an expired proposal on retry, a
future-issued proposal, and a metadata-only operation incorrectly reported as an
idempotent physical reservation. The valid replay control passed. The nonce case
could strand an operation that recovery correctly refused to load; it did not
enable a nonce-backed runtime or establish an observed tool-dispatch bypass.

Command identity, proposal lifetime, each individual token lifetime and request
binding are checked before the idempotent branch. A replay must find the exact
reserved proposal and complete canonical token inventory under the current
fenced transaction. Matching operation attachments alone do not establish that
physical reservation. Blob equality is evaluated inside SQLite without loading
corrupt stored blobs into Rust. Expired artifacts remain replay tombstones, not
renewed authority.

Ten new regressions cover those failures, an unrelated supplemental attachment,
independent token expiry and future issuance, unchanged exact replay and reopen,
four injected SQL failures, and missing or altered proposal/token records.
Fault injection checks the intended SQL error and verifies that operation state,
admission commits and participant rows do not partially advance. The exact CI
inventory names all ten tests.

This is qualification of the threshold reservation write/retry boundary, not a
new all-state threshold restoration or process-crash qualification. Generic
approval metadata remains available for the existing non-threshold approval
path; it cannot substitute for physical evidence at this threshold replay port.
At this threshold-reservation checkpoint, durable nonce commit/cancellation,
issuance and cross-profile replay composition, strict preflight identity,
recovery ownership and the original release gates remained open. The next
section extends the SQLite participant, not runtime activation. No nonce-enabled
runtime, publication, deployment or automatic response was enabled.

Local verification uses Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. Both exact
inventory steps were executed from the actual workflow YAML.

| Boundary | Result |
| --- | --- |
| Exact threshold reservation qualification | Ten passed, zero failed or ignored |
| Exact durable nonce reservation | Ten passed, zero failed or ignored |
| Full SQLite library, eight test threads | 1,153 passed, zero failed, three existing ignored |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Legacy SQLite nonce-store integration | Eight passed, zero failed or ignored |
| Kernel collector SQLite restart integration | Nine passed, zero failed or ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |

The full SQLite run completed in 324.16 seconds. Exact and focused counts overlap
the full suite. Its ignored entries remain the receipt-retention property test
quarantined under issue #1045, the large-history receipt scale proof, and the
subprocess-only owner helper. The parent test executed that helper successfully;
neither unexecuted receipt test is qualified by this run.

Formatting, diff whitespace, changed-workflow actionlint, public-surface policy
and its self-tests, security CI contracts and mutation tests, exact-inventory and
runner self-tests, and file-hygiene self-tests passed.

Full file hygiene still reports the same 22 inherited failing files. Formal
mirror checking still reports seven inherited drift entries across four unchanged
Rust files. No cap or formal proof hash was changed. The regenerated proof
inventory matches 58 rows and 166 artifacts; inventory consistency does not
establish new proof coverage. Full-workspace, exact-head hosted, native, package
and observed-pilot qualification remain open.

## Durable nonce capture and cancellation in the owning SQLite transaction

Schema version 13 adds bounded, append-only nonce phase snapshots authenticated
by their exact admission commits. The original globally unique reservation row
remains permanent. Reads and bootstrap verify canonical snapshots, immutable
operation binding and retained attachments, phase ordering, historical validity,
participant commitments and ownership. An expired signature does not invalidate
historical evidence or permit reuse of a cancelled nonce.

The default-deny `begin_execution_nonce_capture` port prepares `CapturePending`
only after checking the current fenced coordinator, nonce issuer, fresh signed
nonce, retained original request and physical authorized budget hold. If this
operation requires threshold approval, preparation and capture also reconstruct
and verify the bounded canonical proposal/token inventory, exact operation
binding and each artifact's current validity window. Metadata attachments alone
do not establish that evidence.

For this co-located SQLite implementation, capture of the real budget hold,
commitment of nonce and reserved approvals, and `DispatchCommitted` share one
transaction. This refines the roadmap's commit-before-capture ordering into one
durable commit point: no captured quota or dispatch commitment is externally
visible without the committed nonce. `CapturePending` itself leaves the nonce
reserved and grants no execution authority. This is not a multi-store or
distributed transaction guarantee.

Pre-dispatch cancellation requires the actual hold to be reversed with no
remaining exposure. The cancellation snapshot and qualified terminal projection
commit together. Neither an asserted release proof nor a generic state update
can substitute for that physical check. A committed nonce is never cancelled or
refunded; qualified post-dispatch terminal paths preserve its committed history.
Standalone legacy budget capture rejects nonce-owned holds, and generic state
updates cannot mutate an operation after nonce reservation. Subsequent tool
outcomes must use the existing atomic outcome participant.

Eighteen exact lifecycle regressions cover real hold capture and release,
preparation/capture/cancellation SQL rollback, current-owner reopen, expired
capture and cleanup, bounded corruption rejection, immutable phase rows, v12
migration, capture-versus-cancel races and composed threshold approval. The
post-dispatch negative control reproduced generic attachment of a nonexistent
tool outcome before the guard was tightened. Its positive control persists a
real canonical outcome through the qualified participant. Fault injection checks
the intended SQL error and every affected participant, not merely an error return.

The exact-capture retry control also reproduced rejection of a previously
committed capture. Replays now validate the complete stored nonce history,
original issuer, exact resulting operation and existing budget participant
commitment, returning the historical result without a second phase or quota
effect. Later retries, including at nonce expiry while the original recovery
lease remains valid, preserve the original commit time. Substituted budget event
identities are rejected. This does not renew expired authorization or authorize
another provider attempt.

These store-level tests do not qualify a nonce-enabled kernel, real provider
execution, process-kill cutpoints or distributed custody. The coordinator still
rejects durable nonce configuration until issuance, strict preflight identity,
cross-profile replay exclusion and runtime/session recovery are integrated.
Kernel-owned governed active-response originals and sidecar composition also
remain open. No runtime profile, automatic response, publication or deployment
was enabled.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. All three
exact inventory steps were executed from the actual workflow YAML.

| Boundary | Result |
| --- | --- |
| Exact durable nonce lifecycle | 18 passed, zero failed or ignored |
| Exact durable nonce reservation | Ten passed, zero failed or ignored |
| Exact threshold reservation qualification | Ten passed, zero failed or ignored |
| Full SQLite library, eight test threads | 1,171 passed, zero failed, three existing ignored |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Full post-quantum kernel library | 1,235 passed, zero failed or ignored |
| Legacy SQLite nonce-store integration | Eight passed, zero failed or ignored |
| Kernel collector SQLite restart integration | Nine passed, zero failed or ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |

The final full SQLite run completed in 316.91 seconds. Exact and focused counts
overlap the full suite. Its ignored entries remain the receipt-retention
property test quarantined under issue #1045, the large-history receipt scale
proof, and the subprocess-only owner helper. The parent test executed that
helper successfully; neither unexecuted receipt test is qualified by this run.

Formatting, diff whitespace, changed-workflow actionlint, public-surface policy
and self-tests, security CI contracts and mutation tests, exact-inventory and
runner self-tests, and file-hygiene self-tests passed. Full file hygiene still
reports the same 22 inherited failing files. Formal mirror checking still reports
seven inherited drift entries across four unchanged Rust files. No cap or formal
proof hash changed. The regenerated proof inventory matches 58 rows and 166
artifacts, without claiming new proof coverage. Full-workspace, exact-head hosted,
native, package and observed-pilot qualification remain open.

## Operation-bound nonce signatures and legacy profile isolation

Two negative controls reproduced acceptance of one legacy signed nonce by both
the operation-owned SQLite admission store and an independent legacy SQLite
replay store, in either order. These were store-level replay-boundary failures,
not an observed tool-execution bypass: durable nonce configuration was and
remains rejected by the kernel coordinator.

New operation-owned nonces use `chio.execution_nonce.v2`. The signature commits
to a canonical, domain-separated context containing the full nonce body and the
trusted operation ID. That ID binds the authenticated namespace, capability
artifact, request, policy and effect class. The presented nonce cannot select
another operation context, even if all six legacy request fields match. The
legacy verifier continues to accept only v1; relabeling either profile invalidates
its signature. Shared claim validation does not share signature authority.

Fresh operation-owned reservation, retry, capture preparation and capture require
the v2 profile. Admission schema version 14 fences previous writers while
preserving authenticated v1 reservation and phase history. Historical decoding
does not establish fresh authority. Genuine v12/v13 canonical fixtures verify
that old ready and capture-pending operations cannot capture a quota, can release
their real holds, and can persist qualified cancellation without deleting their
nonce tombstones. Already committed capture retries remain historical reads,
without a second nonce phase, quota effect or provider authorization.

Eight new profile regressions cover both replay-store orderings, authenticated
namespace and policy context substitution, schema relabeling, all six binding
fields, mint arithmetic and canonical decoding, and the two legacy migration
states. CI names the exact test inventory. The wire-schema regression preserves
both transport profiles and rejects unknown versions and incomplete binding.
Shared cross-language fixtures include both profiles and reject caller-supplied
top-level operation context. Existing generators update Rust, TypeScript, Python
and Go bindings; the broad Python diff is generated schema-hash propagation.
Running the generated Rust fixture corpus also exposed and fixed its missing
decoder mapping for the existing pending-approval fixture. CI now names that
whole-corpus test explicitly.

The checked mint factory only creates signed material. It neither persists a
unique issuance nor proves authorization, reservation or dispatch. Durable
preflight issuance must still prevent reminting after a lost acknowledgement,
keep the compensated internal hold distinct from the executable hold, and retain
permanent cleanup evidence. Kernel routing, ownership and session recovery,
process-kill qualification, governed active-response originals and sidecar
composition remain open. No nonce-enabled runtime, automatic response,
publication or deployment was enabled.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. Six exact
inventory steps were executed from the actual workflow YAML.

| Boundary | Result |
| --- | --- |
| Exact nonce profile isolation | Eight passed, zero failed or ignored |
| Exact nonce reservation and lifecycle | Ten and 18 passed, zero failed or ignored |
| Exact threshold reservation qualification | Ten passed, zero failed or ignored |
| Full wire-schema suite | Nine passed, including the one exact profile test |
| Exact generated Rust shared-fixture corpus | One passed, zero failed or ignored |
| Full SQLite library, eight test threads | 1,179 passed, zero failed, three existing ignored |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Full post-quantum kernel library | 1,235 passed, zero failed or ignored |
| Legacy nonce-store and kernel restart integrations | Eight and nine passed, zero failed or ignored |
| Python SDK suite | 176 passed |
| Go SDK package tests and changed-test formatting | Passed |
| TypeScript shared-fixture test and type checking | Passed |
| Rust, TypeScript, Python and Go generation checks | All in sync |
| Kernel, SQLite and core-type libraries/tests Clippy | Passed with warnings denied |

The final SQLite run completed in 324.44 seconds. Its first attempt had one test
infrastructure failure: an overlapping rebuild replaced the running executable
before the ownership test spawned its helper, producing `ENOENT`. The focused
ownership test and complete suite passed without an overlapping rebuild; no test
or production behavior was weakened. The three existing ignored tests remain the
receipt-retention property test quarantined under issue #1045, the large-history
receipt scale proof and the subprocess-only owner helper. The parent executed
that helper successfully. Neither unexecuted receipt test is qualified.

TypeScript type checking required building the existing local `node-http`
workspace dependency first, without source or dependency changes. The Python
suite used the SDK's existing virtual environment. Exact, focused and full-suite
counts overlap and are not additive.

Formatting, diff whitespace, changed-workflow actionlint, public-surface policy
and self-tests, security CI contracts and mutation tests, exact-inventory and
runner self-tests, and file-hygiene self-tests passed. Full file hygiene still
reports the same 22 inherited failing files; formal mirrors still report seven
inherited drift entries across four unchanged Rust files. No cap or formal proof
hash was changed. The regenerated proof inventory matches 58 rows and 166
artifacts, without establishing additional proof coverage. Full-workspace,
exact-head hosted, native, package and observed-pilot qualification remain open.

## Write-ahead nonce issuance in the owning SQLite transaction

Admission schema version 15 adds permanent nonce issuance rows, unique by both
operation and nonce ID. Issuance attaches the exact canonical artifact digest to
the same `Prepared` operation and advances its version in one transaction. The
operation ID and authenticated namespace do not change. This is an issuance
reference, not the separate nonce reservation reference or a dispatch permit.
Older canonical operations remain byte-compatible when the new attachment is
absent; previous writers are fenced by the store schema version.

The default-deny issuance port checks the exact command, current ownership and
lease, coordinator-pinned issuer, retained original request, operation-bound
signature profile, current validity window and canonical artifact bounds.
Issuance precedes executable participants. Its immutable row retains the signed
bytes, prepared snapshot and authoritative time; reads verify all fields against
the exact admission commit and the operation's retained attachment. Missing,
altered, oversized or orphaned evidence fails closed. Generic CAS and prepared
begin cannot fabricate the attachment.

A lost acknowledgement is recovered through fenced lookup of the same artifact.
An exact live issuance retry under a current recovery lease is idempotent. The
original command's stale version-bound lease remains fenced after its commit.
Neither a different candidate nor expiry can replace the original bytes or
recycle its identity. Expired artifacts
remain available as history, not renewed delivery or execution authority. The
global nonce-ID collision check now occurs at issuance, before reservation;
concurrent valid signatures for different authenticated operations cannot both
acquire that identity. Competing candidates for one operation likewise have one
durable winner.

Fresh reservation requires the exact issued artifact. Capture preparation and
capture independently require its durable issuance provenance. Two migration
controls initially demonstrated that these capture checks were missing from the
partially integrated issuance path: a genuine v14 ready record could prepare
capture, and a v14 capture-pending record could capture real quota despite having
no issuance row. Both now reject before any capture effect survives. Old records
can still release their physical holds and persist qualified cancellation without
inventing issuance. Already committed results remain historical replay, without
another quota or nonce effect. These are store-level controls, not evidence of
an enabled kernel profile or observed provider bypass.

Thirteen new issuance regressions cover exact retry and expiry, changed
candidates, same-operation races, generic and begin forgery, wrong profiles and
issuers, three injected SQL cutpoints, migration/current fences, required
original provenance, command isolation, reservation binding, late issuance and
six corruption cases. The existing cross-namespace collision regression now
competes at the issuance boundary. CI names the exact inventories. History
verification also uses read-only attachment slices instead of cloning complete
operation snapshots for each subset check.

This closes durable persistence of one issued artifact, not physical preflight
ownership or cleanup. The store still allows one executable hold per operation.
The caller must finish current authorization and qualified preflight cleanup
before issuance, then revalidate before delivery. Integrating a distinct internal
preflight hold, permanent cleanup evidence and the separate executable hold
remains required; a compensated operation or hold must never be reopened and an
invented tenant/coordinator namespace must never disguise a second identity.
Kernel routing, session recovery, drop/shutdown/process cutpoints, governed
active-response originals and sidecar composition remain open. Durable nonce
configuration is still rejected by the kernel coordinator. No runtime profile,
automatic response, publication or deployment was enabled.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. All seven
exact inventory steps ran from the actual workflow YAML. The final issuance gate
also discarded the first acknowledgement, confirmed that its original
version-bound command stays fenced, then recovered the same artifact and
confirmed idempotence under a fresh lease. This preserves the existing lease
contract rather than exempting stale commands from fencing.

| Boundary | Result |
| --- | --- |
| Exact durable nonce issuance | 13 passed, zero failed or ignored |
| Exact nonce reservation and lifecycle | Ten and 18 passed, zero failed or ignored |
| Exact nonce profile isolation | Eight passed, zero failed or ignored |
| Exact threshold reservation qualification | Ten passed, zero failed or ignored |
| Exact wire-profile and generated Rust fixture gates | One each passed, zero failed or ignored |
| Final full SQLite library, eight test threads | 1,192 passed, zero failed, three existing ignored |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Full post-quantum kernel library | 1,235 passed, zero failed or ignored |
| Legacy nonce-store and kernel restart integrations | Eight and nine passed, zero failed or ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |

The final SQLite run completed in 339.58 seconds. Exact and full-suite counts
overlap. The existing ignored entries remain the receipt-retention property test
quarantined under issue #1045, the large-history receipt scale proof and the
subprocess-only owner helper. Its parent executed the helper successfully;
neither unexecuted receipt test is qualified by this run.

Formatting, diff whitespace, changed-workflow actionlint, public-surface policy
and self-tests, security CI contracts and mutation tests, exact-inventory and
runner self-tests, and file-hygiene self-tests passed. The same 22 inherited
file-hygiene failures and seven formal-mirror drifts across four unchanged Rust
files remain open. No cap or formal proof hash was changed. The regenerated
proof inventory matches 58 rows and 166 artifacts, without establishing new
proof coverage. No wire schema or generated SDK binding changed in this
milestone. Full-workspace, exact-head hosted, native, package and observed-pilot
qualification remain open.

## Operation-owned physical nonce preflight

Admission schema version 16 records one permanent internal preflight budget
participant per parent operation. Its typed identity derives a reserved budget
operation ID from the parent admission ID, with grant-bound hold and authorization
event IDs. The parent admission ID, authenticated tenant/coordinator namespace,
request binding and replay identity do not change. The existing unique budget
hold index remains unchanged. A preflight hold and the subsequent executable hold
belong to distinct, explicit budget participants; neither a compensated operation
nor a reversed hold is reopened.

The preflight port reuses the composite budget transaction for grant and aggregate
invocation quotas, monetary exposure and cumulative approval reservations. An
explicit participant enum separates executable authorization from preflight
ownership. Physical authorization, the bounded canonical ownership row, its
immutable attachment on the same `Prepared` admission and both authority commits
persist together. The port checks the current lease, retained original request,
selected matching grant and exact derived identifiers. Denial retains its budget
event but creates no physical hold or ownership. Generic budget writers, including
the in-memory implementation, cannot allocate the reserved internal identity.
Generic admission begin and CAS cannot fabricate the ownership attachment.

Exact live retries require a current version-bound recovery lease. A lost
acknowledgement is recovered by loading the committed admission and its fenced
preflight identity before retrying or cleaning up. The original stale command
remains fenced. Replay cannot backfill ownership for an existing physical
authorization, replace the selected grant or recycle the hold after reversal.
The lookup returns identity data, not a cleanup certificate or dispatch authority.

Preflight holds cannot capture invocation quota or settle monetary spend.
Cleanup uses the existing durable reversal, including every composite quota and
cumulative account participant. A subsequent issuance transaction rechecks that
physical reversal and its permanent history. Historical issuance verification
also requires the reversal's global authority commit to precede the issuance
commit. A crash between reversal and issuance can recover the same reversed hold;
no rollback or ownership row is invented. Releasing a pending cumulative approval
does not establish authorization: issuance still fails unless its required budget
approval completed before cleanup.

Fresh issuance, reservation, capture preparation and capture require owned,
reversed preflight evidence. Genuine v15 issuance/ready/capture-pending records
without that evidence remain readable history, not fresh authority. Their
physical executable holds can still be reversed and qualified cancellation can
persist without fabricating preflight. Historical already-committed replay
remains read-only. Canonical operations without the new optional attachment keep
their previous bytes, and earlier admission writers are fenced by schema version.

Ownership reads are bounded before allocation and check exact canonical data,
derived identifiers, the retained original grant, the prepared snapshot and its
admission commit, and the authorization's physical budget projection. Immutable
rows cannot be updated or deleted. Missing, altered, oversized or orphaned
evidence fails closed. Read-only composite budget loaders now accept a connection
view so ownership verification can reuse the same projection checks within its
owning snapshot; mutation helpers still require the existing transaction.

Fifteen preflight regressions cover the full physical reserve/reverse/execute
sequence, forbidden capture, lost acknowledgements, ownership races, three SQL
rollback cutpoints, seven request mutations, generic identity/attachment forgery,
denial, six corruption cases, original provenance, late acquisition, replay
backfill rejection, composite quota/approval cleanup and three v15 migration
boundaries. Existing nonce fixtures now perform real owned preflight and reversal
before fresh issuance. Older migration fixtures retain their actual old shape;
they acquire new ownership only after reopening under the current writer. CI
names the exact preflight inventory separately from issuance and lifecycle tests.

This is a store-level budget preflight boundary, not complete kernel preflight.
Current capability/guard authorization, broker and sibling-budget lease cleanup,
nonce delivery, session recovery, kernel routing and drop/shutdown/process-kill
cutpoints still require integration and qualification. Governed active-response
originals, sidecar composition and witnessed custody remain open. Durable nonce
configuration is still rejected by the kernel coordinator. No automatic response,
runtime profile, public traffic, package publication or deployment was enabled.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory, against the
staged tree over `207420dcaa`. All eight exact inventory steps ran from the
actual workflow YAML. The preflight inventory ran first and separately from the
issuance, reservation and lifecycle inventories.

| Boundary | Result |
| --- | --- |
| Exact durable nonce preflight ownership | 15 passed, zero failed or ignored |
| Exact durable nonce reservation, lifecycle and issuance | Ten, 18 and 13 passed, zero failed or ignored |
| Exact nonce profile isolation | Eight passed, zero failed or ignored |
| Exact threshold reservation qualification | Ten passed, zero failed or ignored |
| Exact wire-profile and generated Rust fixture gates | One each passed, zero failed or ignored |
| Full SQLite library, eight test threads | 1,207 passed, zero failed, three existing ignored |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Full post-quantum kernel library | 1,235 passed, zero failed or ignored |
| Legacy nonce-store and kernel restart integrations | Eight and nine passed, zero failed or ignored |
| Kernel and SQLite libraries/tests Clippy | Passed with warnings denied |

The final SQLite run completed in 364.61 seconds. Exact and full-suite counts
overlap. The existing ignored entries remain the receipt-retention property test
quarantined under issue #1045, the large-history receipt scale proof and the
subprocess-only owner helper; its parent executed the helper successfully.

Formatting, diff whitespace, changed-workflow actionlint, public-surface policy
and self-tests, security CI contracts and mutation tests, exact-inventory and
runner self-tests, and file-hygiene self-tests passed. No cap or formal proof
hash was changed. The regenerated proof inventory matches 58 rows and 166
artifacts, without establishing new proof coverage. No wire schema or generated
SDK binding changed. Full-workspace, exact-head hosted, native, package and
observed-pilot qualification remain open.

## Kernel routing of the operation-owned nonce participant

The kernel coordinator now routes strict execution nonces through the durable
admission operation instead of rejecting every configured nonce profile. A
request under durable coverage with `require_nonce` set begins an operation
whose participant requirements include the execution nonce and always retains
the original request. An opt-in nonce profile, a store without the participant
capability, a cumulative-approval grant and the sidecar reserve-for-caller
authorization each deny before any participant is acquired; the projection
capability set names the participant explicitly so a store that cannot retain
issuance fails closed at the same point.

A preflight request keeps the operation `Prepared`. The budget step authorizes
the internal preflight hold through the store's owned participant with the
derived identity, never the executable hold identity, and without a payment
journal. Cleanup reverses that hold through the same deterministic rollback
event the executable path uses, then issuance mints the operation-bound nonce
from the retained original request and retains it with the operation. The
preflight receipt delivers the retained signed nonce; the legacy replay store
neither mints nor sees it. A repeated preflight for the same request replays the
owned cleanup if the hold is still reserved and redelivers the retained issuance
while it is live; an expired issuance denies until startup recovery compensates
the operation. Governed approval reservation is deferred to the execution request.

An execution request binds the presented nonce to the retained issuance before
any mutation: absent, foreign, tampered or expired material denies without
touching the operation. The broker attempt is then registered, bound to the
operation's coordinator epoch so a replay under a later serving owner still
matches. The executable hold, approvals, nonce reservation with
`ReadyToDispatch`, capture preparation with `CapturePending` and the combined
capture commit follow in the store's order; the legacy nonce validation at the
credential and pre-dispatch gates is bypassed only for operations whose nonce
the store already verified. A completed request replays its retained receipt
for the same spent nonce without executing again.

Recovery treats a `Prepared` operation with a live issuance as quiescent and
compensates it only after the nonce expires. Compensation of any pre-dispatch
operation first reverses a still-reserved preflight hold, and the SQLite store
refuses a nonce terminal while that hold is reserved. A cleanup failure poisons
the SQLite authority by design; the next process compensates the operation and
restores the quota, and an in-process retry replays the exact reversal when the
authority is still serving.

Thirteen kernel-against-SQLite regressions cover preflight and single
execution, preflight replay without a second hold, foreign and tampered
nonces, restart between preflight and execution with a later replay, expired
issuance and its startup compensation, live issuance surviving recovery until
expiry, an injected rollback cutpoint compensated at startup and replayed in
process, budget exhaustion at execution, the cumulative-approval, opt-in and
reserve-for-caller denials, and session-flow parity. CI names that inventory.

This routes the participant; it does not qualify delivery to remote tool
servers, governed active-response originals, sidecar composition, cumulative
approval under strict preflight, or drop, shutdown and process-kill cutpoints
inside the execution request. No automatic response, runtime profile, public
traffic, package publication or deployment was enabled.

The startup recovery sweep moved from the coordinator into
`admission_coordinator/recovery.rs`, and the projection capability set moved into
`admission_operation/projection/capabilities.rs`, keeping both parents under
their ordinary limits without raising any cap. The control-plane library test
module regained the error-code imports its diagnostic split had dropped, so that
crate's test target compiles again; one of its scheduler-worker liveness tests
failed once under concurrent builds and passed twice in isolation.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. All exact
inventory steps ran from the actual workflow YAML, including the new kernel
participant lifecycle step.

| Boundary | Result |
| --- | --- |
| Exact kernel nonce participant lifecycle | 13 passed, zero failed or ignored |
| Exact kernel collector restart lifecycle | Nine passed, zero failed or ignored |
| Exact durable nonce preflight ownership | 15 passed, zero failed or ignored |
| Exact durable nonce reservation, lifecycle and issuance | Ten, 18 and 13 passed, zero failed or ignored |
| Exact nonce profile isolation | Eight passed, zero failed or ignored |
| Exact threshold reservation qualification | Ten passed, zero failed or ignored |
| Exact wire-profile and generated Rust fixture gates | One each passed, zero failed or ignored |
| Full SQLite library, eight test threads | 1,207 passed, zero failed, three existing ignored |
| Full default kernel library | 1,199 passed, zero failed or ignored |
| Full post-quantum kernel library | 1,235 passed, zero failed or ignored |
| Legacy nonce-store integration | Eight passed, zero failed or ignored |
| Control-plane library | 976 passed, one load-sensitive failure that passed twice in isolation |
| Kernel, SQLite and control-plane libraries/tests Clippy | Passed with warnings denied |

The final SQLite run, on the tree after the module split, completed in 358.06
seconds. Exact and full-suite counts overlap. The existing ignored entries remain
the receipt-retention property test quarantined under issue #1045, the
large-history receipt scale proof and the subprocess-only owner helper; its
parent executed the helper successfully.

Formatting, diff whitespace, changed-workflow actionlint, public-surface policy
and self-tests, security CI contracts and mutation tests, exact-inventory and
runner self-tests, and file-hygiene self-tests passed. The same 22 inherited
file-hygiene failures remain open; three of those files grew by a few lines in
this milestone and no cap was raised. The regenerated proof inventory matches
58 rows and 166 artifacts, without establishing new proof coverage. No wire
schema or generated SDK binding changed. Full-workspace, exact-head hosted,
native, package and observed-pilot qualification remain open.

## Recovery of retained executable holds

Startup recovery compensated every non-terminal pre-dispatch operation without
touching the budget it still held. A coordinator that died after authorizing the
executable hold therefore leaked that reservation permanently, and a nonce
operation that died after reserving its nonce could not be compensated at all,
because the store refuses a nonce cancellation while the executable hold is
still authorized. Both were reproduced against the real kernel and SQLite
authority before the change: an injected capture-preparation cutpoint left a
`ReadyToDispatch` nonce operation whose next startup failed with a budget
disposition invariant, and the kernel-level recovery of a `BudgetAuthorized`
operation left its hold open.

Pre-dispatch compensation now reverses the retained executable hold through the
budget authority before it releases an owned preflight hold and before it
projects the terminal. The reversal reads the hold's physical snapshot, verifies
its capability, does nothing for a hold the live path already reversed, and
otherwise reverses the remaining exposure with a deterministic recovery rollback
event, so repeated recovery stays idempotent. A committed dispatch is never
reversed. The SQLite terminal projection additionally refuses any
`CompensatedBeforeDispatch` terminal, signed or plain, while the operation's
structured hold is still authorized; a hold that was never physically created
has nothing to leak and does not block compensation.

The kernel test that drops an execution after the tool server is invoked shows
the other side of the dispatch commit: the drop guard records the cancellation,
terminalizes the operation as outcome unknown, the captured invocation is never
reversed, and a retry with the same nonce denies before and after restart.

Nineteen regressions qualify this: the fifteen kernel-against-SQLite nonce
lifecycle tests, now including the reserved-nonce startup compensation and the
post-commit drop, the kernel recovery test for a `BudgetAuthorized` operation,
the store-level refusal of an unreleased executable hold, and the existing
recovery and compensation suites. CI names the extended inventory. The
post-commit drop test needs an async runtime, so the SQLite store crate gained a
`tokio` development dependency; the resulting workspace lockfile delta is that
single dependency edge, with no third-party package version or checksum change,
and both evidence-container lockfile pins moved to
`f845b053912810d171a412bf0042efcfed78acb068c6cc3419931de492232d83`. Process-kill
cutpoints inside the execution request, delivery to remote tool servers,
sidecar composition and cumulative approval under strict preflight remain open.
No automatic response, runtime profile, public traffic, package publication or
deployment was enabled.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. The exact
inventory steps ran from the actual workflow YAML.

| Boundary | Result |
| --- | --- |
| Exact kernel nonce participant lifecycle | 15 passed, zero failed or ignored |
| Exact kernel collector restart lifecycle | Nine passed, zero failed or ignored |
| Exact durable nonce preflight ownership and lifecycle | 15 and 18 passed, zero failed or ignored |
| Full SQLite library, eight test threads | 1,208 passed, zero failed, three existing ignored |
| Full default kernel library | 1,200 passed, zero failed or ignored |
| Full post-quantum kernel library | 1,236 passed, zero failed or ignored |
| Core types, binding helpers and FFI bindings | All passed, zero failed or ignored |
| Kernel, SQLite, control-plane, core and binding crates Clippy | Passed with warnings denied |

The final SQLite run completed in 366 seconds. Exact and full-suite
counts overlap. The existing ignored entries remain the receipt-retention
property test quarantined under issue #1045, the large-history receipt scale
proof and the subprocess-only owner helper; its parent executed the helper
successfully. Formatting, diff whitespace and changed-workflow actionlint passed.
The regenerated proof inventory matches 58 rows and 166 artifacts, without
establishing new proof coverage. No wire schema or generated SDK binding changed.

## Hosted qualification triage, 2026-09-06

The integrated candidate was pushed as draft pull request #1117 to obtain
exact-head hosted evidence. The first hosted run separated four kinds of
failure; none was hidden or waived.

Branch regressions repaired in source:

- The sidecar and TEE images failed to build because the vendored
  `third_party` workspace members introduced with the verified manifest and
  cage boundary were never copied into any Docker build context that loads the
  workspace manifest. The two sidecar Dockerfiles, the TEE Dockerfile and the
  cognition market Dockerfile now copy them. The CLI image builds from a
  generated product workspace whose generator dropped the root
  `[patch.crates-io]` section, so that image would have resolved the upstream
  `sigstore-verify` instead of the vendored fork; the generator now carries the
  patch section, the generated manifest and lock are regenerated, and the
  workspace check links the vendored members.
- A new structural gate, `scripts/check-docker-build-contexts.py`, derives
  from `cargo metadata` the path packages each Docker stage's workspace
  resolves and fails when the stage's `COPY` lines do not cover them. It found
  two defects that predate this source: the documented sidecar Dockerfile under
  `deploy/sidecar` never copied the bench, integration and xtask members, and
  the proof room quickstart stage built from a hand-maintained trimmed
  workspace whose manifest no longer resolved on main. The proof room stage
  now builds from the repository workspace and the trimmed workspace is
  removed. Locally, the proof room binary built in release from the
  repository workspace, the CLI image workspace check passed against a fresh
  target directory, the gate covers six build stages, and its self-test
  rejects a root stage and a product stage that omit the vendored members.
  The images themselves were not built here.
- The ClusterFuzzLite changed-target lane failed to compile the ACP-Client edge fuzz
  entry point, which still constructed the edge from a manifest list after the
  edge began requiring a verified manifest registry. The entry point now
  constructs an empty registry; every crate with a `fuzz` feature compiles
  with it enabled.
- With the vendored members in place, both sidecar image architectures failed
  in the cage crate: its descriptor passing assigned `usize` control lengths
  to `msghdr` and `cmsghdr` fields that are `socklen_t` on musl, the C library
  of the Alpine images. The lengths now convert through the field's own type
  and the arithmetic stays in `usize`; the crate compiles on Alpine musl in the
  sidecar's own Rust image.
- The Windows authority lane, once past the gated test, failed to compile the
  active response authority crate, whose runtime and store are unix-only (unix
  sockets, effective identity, signals) but were built unconditionally as a
  CLI dependency. Those two modules and their exports are now unix-only at the
  crate root, the CLI's authority store commands refuse on other platforms,
  and the deployment digest and validation commands stay portable. No Windows
  toolchain is available here; the hosted lane is the verification.
- Both public Kani lanes refused to build because the security types crate
  inherited the workspace minimum Rust version, 1.94, while the Kani toolchain
  is a 1.93 nightly; the crates already covered by Kani harnesses pin 1.93
  explicitly. The security types crate now carries the same pin, and the
  toolchain parity check and its self-test pass.
- The fuzz corpus smoke lane, an advisory lane, could not build the
  standalone fuzz workspace under `--locked` because its own lockfile predates
  the vendored verifier and the schema tooling the security source added to
  the fuzzed crates' dependency closure. The fuzz lockfile is regenerated,
  resolves locked, every fuzz target compiles and the workspace's smoke test
  passes locally; the changed-target lane had not noticed because it only
  reads the workspace metadata without dependencies before building.
- The workspace structural gates failed at the schema registry check: 64
  security schemas had been added under `spec/schemas` without entries in the
  schema manifest. The manifest is regenerated with the gate's own
  deterministic rules. The same step's review-slice check then had no slice
  for the security crates, the vendored members or the notice file, so the
  branch-wide diff could not be partitioned; two slices now name them, and the
  branch partitions into fourteen slices.
- The supply-chain advisory lane reported that `der` 0.8.0, pinned by main
  as well, was yanked upstream after the candidate was cut. The lockfile now
  resolves `der` 0.8.2, the lockfile digest pins, the generated CLI image
  workspace and the fuzz lockfile follow it, and cargo-deny passes locally.
  This is an ecosystem event, not a regression of the security source.
- The proof room release-truth copy lint rejected three ledger sentences that
  named the agent client protocol edge with the bare protocol acronym; the
  ledger now uses the qualified name the rest of the documentation uses.
- The reviewed duplicate-version baseline behind cargo-deny drifted: the
  vendored `nono` cage library pulls `typify` 0.6 with its `regress` 0.11
  beside the 0.4 and 0.10 the spec code generator still pins, and the `der`
  replacement moved that crate's line.
  Unifying the generator on `typify` 0.6 would change generated bindings and
  is deferred; the baseline is refreshed to the reviewed inventory.
- The live C++ conformance and SDK parity lanes stalled on the first durable
  `tools/call` after remote delivery landed: the MCP stdio probe sent a `ping`
  before each durable dispatch, and the harness upstream never answers one, so
  the dispatch waited until the lane timed out. The probe now proves the
  child process is running without a round trip.
- Bounded cryptographic wire decoding classified malformed signer text as an
  invalid key instead of invalid hex, breaking the binding helper contract,
  the FFI trusted-signer error code checked by the SDK parity and transitive
  surface lanes, and the C++ SDK smoke on every platform. Decoding now rejects
  oversized input by size alone, then classifies any non-hex text as invalid
  hex before any length or material check; a bounds regression covers both
  orders. The first correction used a std-only string conversion, which the
  wasm-pack lane rejected in the no_std build of the core types; the decoder
  now uses the module's own conversion, verified by a wasm32 no_std check of
  the core types and of the browser kernel. The FIPS smoke workflow's exact
  wire-bounds inventory did not name the new bounds regression and failed on
  the unexpected test; the inventory now names it.
- The Windows authority lane failed to compile because a control-plane event
  consumer test used wire types that exist only in the unix-gated authority
  module. The test is gated the same way.
- The eval receipt and byte-stable vector lanes reported a stale vector digest
  manifest: 39 security vectors had been added without regenerating it. The
  manifest was regenerated from the committed vectors and both checks pass.

Operator decisions recorded, not taken here:

- `cargo vet --locked` reports 22 dependencies without a `safe-to-deploy`
  audit: the sigstore family (`sigstore-bundle`, `sigstore-crypto`,
  `sigstore-merkle`, `sigstore-rekor`, `sigstore-trust-root`, `sigstore-tsa`,
  `sigstore-types`), `cmpv2`, `cms`, `crmf`, `x509-tsp`, `der` 0.8.2 (the
  replacement for the yanked release), `landlock`, `seccompiler`, `nono`,
  `enumflags2` and `enumflags2_derive`, `ignore`, `regress`, and `typify` with
  `typify-impl` and `typify-macro`. Each needs an audit or a justified
  exemption; no exemption was added. The hosted cognition market lane runs the
  same gate and fails on the same list.
- The public Kani lane failed its harness parity gate: the gate the
  integration restored requires six protocol harnesses and only four existed.
  The two missing ones, captured invocation count monotonicity and replay
  fingerprint uniqueness, are now bounded predicates in the formal core with
  their proofs enrolled in both manifests; both proved locally with
  cargo-kani 0.67.0 on the pinned nightly.
- The non-core Kani sweep failed because `chio-manifest` and
  `chio-sqlite-file-identity` declared a Rust floor above the Kani toolchain;
  both are pinned to 1.93 like the security types crate and compile under
  rustc 1.93.0, and the anchor harness the sweep stopped at now verifies
  locally under the Kani toolchain.
- The workspace build lane fails at the restored admin-credential contract
  (`scripts/check-mcp-admin-credential-contract.py`): it demands a dedicated
  `--admin-token` at every shipped hosted-MCP launch and a docker entrypoint
  that separates three credentials, but this branch received neither the
  launch surfaces nor the entrypoint the gate describes; three documentation
  pages and five example launchers pass no admin credential and the
  inventoried Python entrypoint does not exist. The gate is not weakened;
  the surface is delivered in "Dedicated admin credentials at every
  hosted-MCP launch" below.
- The MSRV workspace lane, which is the only hosted x86_64 compile of the
  cage crate's tests, fails on the seccomp exec-filter test: it uses the
  test-support prelude that its module never imports, so the code that only
  compiles on x86_64 never compiled anywhere this integration could run.
  The module imports the prelude under the same architecture gate; the fix
  is verified by the lane itself, since this host has no x86_64 C toolchain
  for the crypto build scripts a cross check needs.
- The enterprise merge-binding attestation calls the reusable hardening
  workflow at definition `eba8cdf3`, which predates main's token authorization
  fix, and the enterprise capture lanes require the reviewed
  `CHIO_AUTHORIZED_SECURITY_SOURCE_SHA` and
  `CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA` variables. Re-pinning the caller
  and both variables to a reviewed definition is a trust decision.

Infrastructure failures with no evidentiary value: the public Kani lane and the
byte-stable vector lane both failed while installing the protobuf compiler on
the hosted runner and must be re-run. One control-plane scheduler liveness test
failed once under concurrent local builds and passed in isolation.

One finding corrects the earlier closeouts: the 22 file-hygiene failures are
not inherited. Main passes the hygiene gate with no failure, so every overage
is growth from the integrated security source, and the hosted cognition market
qualification lane is red because of it. Eight production files exceed their
limits, from one line (`chio-ollama-tools-adapter/src/lib.rs`) to 266 lines
(`kernel/dispatch.rs`), and fourteen test suites exceed theirs, most by a few
lines and four by more than a hundred. Restoring that gate by splitting
production files and re-homing oversized suites, without raising any cap, is
the next milestone.

## File hygiene restoration

The integrated security source grew 22 Rust files past the hygiene gate's limits
while main stayed clean, and the hosted cognition market qualification lane was
red because of it. The gate's policy is that allowlist caps only shrink and
expiries only advance through its own ratchet, so no cap or expiry was edited.
Every file was brought under its limit by moving one cohesive unit into a
sibling module in the convention its neighbours already use: `include!`
fragments where the file is itself a fragment of a flat test scope, `#[path]`
modules beside existing ones, and plain `mod` files under a directory the file
already owns. Moved code is unchanged; nothing was deleted except two dead
section banners.

Production files: the security pre-dispatch hook and its commitment derivation
left `kernel/dispatch.rs` for `dispatch/security_pre_dispatch.rs`, with the
timer probe tests beside it; the strict-nonce preflight of the asynchronous
evaluation core became a kernel method in `evaluation/async_nonce_preflight.rs`;
grant selection for nested flows became `evaluation/nested_flow_grant_selection.rs`;
the SQLite finding pool ledger and receipt store, the API-protect mediated
proxy and the Ollama adapter moved their unit test modules into files. Test
suites: the kernel budget, runtime, execution nonce, session and support
fragments each re-homed one group; the control-plane cluster, challenge, market
exit and wedge purchase suites gained one submodule each; the CLI MCP serve
suite moved its embedded mock server script; the A2A and ACP-Client edge suites, the
MCP edge runtime suite, the remote MCP suite and the runtime-core admission
suite each re-homed one section.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. Every
relocated test was run by name and counted against the number moved before the
owning crate's full suite ran.

| Boundary | Result |
| --- | --- |
| Rust file hygiene gate and its self-test | Zero failures from 22; four entries dropped, no cap raised, no expiry changed |
| Full default and post-quantum kernel library | 1,200 and 1,236 passed, zero failed or ignored |
| Control-plane library | 977 passed, zero failed, liveness test passed first run |
| SQLite ledger and receipt classifier suites | 23 relocated tests passed with two neighbours the filter matched |
| API-protect mediated suites | 48 relocated and three boundary tests passed |
| CLI MCP serve HTTP suite | 42 passed, one existing ignored; 43 listed names identical to before |
| Runtime-core admission suite | 46 passed, zero failed |
| A2A, ACP-Client, MCP edge, remote MCP and Ollama libraries | 95, 91, 107, 51 and 33 passed, zero failed |
| Workspace Clippy, all targets, warnings denied | Passed |
| Workspace formatting and security CI contract | Passed |

Twenty-seven sibling modules were created and four allowlist entries removed
because their files fell under the base limit. Seven `include!` test fragments
carry formatting drift the workspace formatter never visits; it predates this
work and was left alone so every parent diff is a pure cut. No wire schema, proof inventory or generated binding
changed.

## Delivery to remote tool servers

The durable admission path committed a dispatch before the tool server was
contacted and treated every failure after the send as an ambiguous side
effect. For an in-process server that is exact; for a remote server it left
two gaps. A transport that could not reach its server at all was
indistinguishable from a request that reached it and timed out, so an
unreachable server cost the captured invocation until an operator restarted
the process. And every post-send error arm disarmed the drop guard without
terminalizing, so the operation stayed non-terminal in the live process and a
replay denied with a state error instead of a deterministic receipt. Nothing
on the wire identified the attempt, so a remote server could not deduplicate.

The tool server boundary now carries a dispatch context: the request id and
the provider attempt the operation registered before any dispatch commits,
whose operation id is the idempotency key the provider attempt contract
already requires. Three defaulted trait methods deliver with that context and
one, `prepare_delivery`, proves reachability before the kernel commits; every
existing implementation compiles unchanged and the blocking adapter forwards
both. A durable dispatch calls the probe after the security pre-dispatch hook
and before the commit, and a failed probe takes the same pre-dispatch cleanup
denial as the hook: credentials rolled back, budget restored, nonce
cancelled, operation compensated. After the send, every error arm of both
evaluation paths terminalizes the operation as outcome unknown before it
builds the ambiguous response, with a fresh trusted timestamp, exactly as the
drop guard does; retained holds are kept and nothing is refunded without
external evidence, so the transport-not-accepted terminal stays reserved for
the provider-status and anchored economic paths.

The MCP adapter forwards the identity in the `_meta` of every durable
`tools/call` under the `chioRequestId` key a Chio edge already treats as the
caller's stable request identity, so a Chio-to-Chio hop deduplicates on the
upstream operation id, together with the operation, attempt and transport key
epoch; its probe proves the upstream child process is still running, because a
`ping` round trip blocks on an upstream that never answers one. The
serializing decorator, the adapted server and the remote MCP shared upstream
forward both methods so no in-tree path drops the identity. The A2A adapter derives the message id of a durable
dispatch from the operation id instead of the wall clock, so a redelivery
presents the same id to the agent.

Qualification runs the real kernel against the SQLite authority and a tool
server behind a loopback TCP socket through the blocking adapter. Four
regressions cover identity on the wire and receipt replay without a second
delivery, an unreachable server compensated before dispatch with a fresh
preflight succeeding once it is back, a connection closed after delivery, and
a response arriving after the transport deadline; the last two terminalize as
outcome unknown in process, keep the captured invocation, deny replay
deterministically before and after restart, and never redeliver. Unit tests
pin the MCP metadata shape, the adapter forwarding and probe, and the A2A
message id. CI names the new inventory. Provider-signed delivery receipts, a
qualified dispatch status probe for ambiguous outcomes, the OpenAPI bridge
context and the sidecar reserve-for-caller composition remain open. No
automatic response, runtime profile, public traffic, package publication or
deployment was enabled.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. The exact
inventory steps ran from the actual workflow YAML with one test thread.

| Boundary | Result |
| --- | --- |
| Exact kernel remote delivery over a loopback socket | Four passed, zero failed or ignored |
| Exact kernel nonce participant lifecycle | 15 passed, zero failed or ignored |
| Full default and post-quantum kernel library | 1,200 and 1,236 passed, zero failed or ignored |
| Kernel integration test binaries | All passed, two existing ignored |
| Full SQLite library, eight test threads | 1,208 passed, zero failed, three existing ignored |
| MCP adapter, MCP edge, remote MCP and A2A adapter libraries | 112, 107, 51 and 109 passed, zero failed |
| Kernel, SQLite and four transport crates Clippy, all targets | Passed with warnings denied |
| Formatting, file hygiene, proof inventory and security CI contract | Passed |

The nonce participant inventory failed once in a chain that ran beside other
builds and passed on every isolated repetition; the failing test was not
captured by that run's filter and the inventory passed again in the final
chain. The asynchronous evaluation core sits 21 lines under its limit after
the probe and the transport-failure terminalization moved into a helper
module and the drop guard; sharing the grant-selection loop the nested flow
already extracted is the next hygiene step for that file. The regenerated
proof inventory matches 58 rows and 166 artifacts, without establishing new
proof coverage. No wire schema or generated SDK binding changed.

## Process-kill cutpoints inside the execution request

The durable admission claims were qualified against drops and aborted futures
inside one process, never against a process that dies mid-request and is
followed by a fresh one. A crash is the case the durable participant exists
for: nothing unwinds, the in-memory poison flag, the replay cache and the
serving lock all vanish with the process, and the successor must reach the
same terminal from the store alone.

The remote delivery suite now runs the execution request in a child process.
The parent provisions the store, runs the preflight, writes the execution
request with its issued nonce, releases the serving owner and starts the test
binary again in a child role that attaches to the same directory with the
same signer and agent keys, so the child is the same kernel claimant the
issuance names. The loopback transport aborts the child's process at a
transport boundary the kernel cannot observe: before anything reaches the
server, after the request is on the wire, or after the response was read but
not yet returned. The parent proves the child died by signal, reopens the
authority as the next process would, and asserts against the store and the
server it still holds.

Three cutpoints qualify: a crash before delivery is compensated by the next
process, its quota restored and the same nonce refused, while a fresh preflight
and execution succeed and the server sees exactly one request; a crash after
the request is on the wire and a crash after the response was read both leave
the operation committed until the next process terminalizes it as outcome
unknown, with the captured invocation kept, the replay denied and no second
delivery. CI names the extended inventory. Cutpoints between the tool return
record and its finalization need a kernel-side hook the transport cannot
provide and remain open, as do the parked approval-required operations and
the sidecar composition.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. The exact
inventory steps ran from the actual workflow YAML with one test thread; each
crash test spawned the test binary as a child process and required a death by
signal.

| Boundary | Result |
| --- | --- |
| Exact kernel remote delivery, now seven tests | Seven passed, zero failed or ignored |
| Exact kernel nonce participant lifecycle | 15 passed, zero failed or ignored |
| SQLite crate Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene and security CI contract | Passed |

The child role attaches to the parent's directory through a borrowed fixture
directory and key seeds passed in the environment; the parent's temporary
directory outlives the child. No wire schema, proof inventory or generated
binding changed.

## Cumulative approval under strict preflight

The kernel coordinator refused to begin any operation that required both the
execution nonce participant and cumulative approval, because the composition
had never been qualified. Below the coordinator the composition was already
representable: the state machine keeps the approval sub-lane orthogonal to
the nonce, the SQLite store reserves a nonce only from `ApprovalReserved` when
approval is required, and the threshold qualification tests already built
operations with both participants. Two things stood in the way. A preflight
hold that evaluated the cumulative threshold could come back approval-required
and, once reversed, was recorded as reversed without approval, which poisons
issuance and cleanup. And the issuance lifetime, meant to bound the window
between preflight and the execution request that binds the nonce, would also
have bounded the approval wait, so an approved retry after the lifetime failed
at the kernel's liveness check and, deeper, at the store's reservation, which
verifies the nonce at the time it is handed in and must never turn an expired
artifact into new authority.

The coordinator gate is gone. A strict nonce preflight authorizes its
provisional hold without the cumulative request, so the preflight never
evaluates approval and the executable hold the execution request takes is the
one that decides it; approval reservation was already deferred to the
execution request. The kernel requires a live nonce only while the operation
is still `Prepared`; once the execution request has bound it, the operation's
own deadlines govern. The store verifies an operation-bound nonce at the
moment the execution request bound it: for an operation that parked for
approval that moment is the creation time of the kernel-signed proposal it
retained, checked to precede the recorded time and to bind the same request,
and every site that verifies a retained nonce, reservation, capture, history
and issuance, uses that one rule, with an issuance recorded before any
proposal exists verified at its own time as before.

The resulting lane is preflight and issuance with the operation `Prepared`,
then on the execution request the broker attempt, the executable hold, the
approval-required transition with the pending-approval receipt, which carries
no nonce, then on the approved retry with the same nonce the cumulative
authorization, the approval reservation, the nonce reservation, capture
preparation and the committed dispatch. Five kernel-against-SQLite regressions
qualify it through the threshold collector: the execution request parks the
operation and a second preflight denies, the approved retry executes once and
replays its receipt before and after restart, the approved retry after the
issuance lifetime still executes, an unbound issuance still expires before
execution, and foreign tokens leave the operation parked. The former denial
regression now shows a runtime without a threshold requirement issuing the
nonce and denying at execution with the operation compensated. CI names the
new inventory. An operation parked for approval that never arrives is not
retired by any path today, for nonce and non-nonce operations alike; the
compensation primitive accepts that source and a retirement sweep is an open
item, as is the sidecar composition.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. The exact
inventory steps ran from the actual workflow YAML with one test thread.

| Boundary | Result |
| --- | --- |
| Exact kernel cumulative approval under strict preflight | Five passed, zero failed or ignored |
| Exact kernel remote delivery | Seven passed, zero failed or ignored |
| Exact kernel nonce participant lifecycle | 15 passed, zero failed or ignored |
| Exact kernel collector restart lifecycle | Nine passed, zero failed or ignored |
| Full default and post-quantum kernel library | 1,200 and 1,236 passed, zero failed or ignored |
| Kernel integration test binaries | All passed, two existing ignored |
| Full SQLite library, eight test threads | 1,208 passed, zero failed, three existing ignored |
| Kernel and SQLite Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene, proof inventory and security CI contract | Passed |

The regenerated proof inventory matches 58 rows and 166 artifacts, without
establishing new proof coverage. No wire schema or generated SDK binding
changed.

## Process-kill cutpoints inside finalization

The kernel finalizes a returned tool call through four durable commits: the
raw return and its outcome record, which move the operation to `Finalizing`;
the post-return evaluation record; the resolved evaluation with its resolved
output; and the terminal projection with the signed receipt, after which the
receipt is appended to the receipt log, mirrored, co-signed for federation and
recorded for memory provenance. A process that dies between any two of those
commits leaves work only the next process can finish, and no transport hook
can reach those points.

The kernel now names them. `DurableFinalizationCutpoint` marks the four
boundaries and finalization reaches each one directly after its commit. The
hook that observes them exists only under the admission test-support feature;
a production kernel carries no hook storage and the reach is a no-op. The
remote delivery suite's child role installs a hook that aborts the process at
the requested cutpoint, so the same harness that already kills the process on
the transport now kills it inside the kernel.

Four regressions run the execution in a child that dies after each commit.
After the return is recorded, after the evaluation begins and after it
resolves, the parent finds the operation `Finalizing`, reopens the authority
without the startup latch, and proves that the recoverable-admission sweep
alone finishes it: exactly one operation reconciles, the state is completed,
the captured quota is retained, the replay answers from the terminal, the
completed receipt reaches the receipt log, and the server saw exactly one
delivery. After the terminal projection the operation is already completed
while its receipt never reached the log; the sweep reconciles nothing and the
next process materializes the projected receipt into the log before the replay
answers. CI names the extended inventory of eleven.

The federation co-signature and the memory provenance entry that follow the
projection are re-derived by the completed replay, not by startup recovery; a
completed operation that is never replayed keeps that gap, recorded here. The
parked approval-required operations and the sidecar composition remain open.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. The exact
inventory steps ran from the actual workflow YAML with one test thread.

| Boundary | Result |
| --- | --- |
| Exact kernel remote delivery | Eleven passed, zero failed or ignored |
| Exact kernel nonce participant lifecycle | 15 passed, zero failed or ignored |
| Exact kernel cumulative approval under strict preflight | Five passed, zero failed or ignored |
| Exact kernel collector restart lifecycle | Nine passed, zero failed or ignored |
| Full default and post-quantum kernel library | 1,200 and 1,236 passed, zero failed or ignored |
| Kernel integration test binaries | All passed, zero failed |
| Full SQLite library, eight test threads | 1,208 passed, zero failed, three existing ignored |
| Kernel and SQLite Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene, proof inventory and security CI contract | Passed |

The regenerated proof inventory matches 58 rows and 166 artifacts, without
establishing new proof coverage. No wire schema or generated SDK binding
changed.

## Retirement of parked approval-required operations

An operation parked for cumulative approval retains its executable budget
hold, its signed proposal and, under the strict nonce profile, its issuance,
and it waited for a token set that might never arrive: the recovery page
excluded every parked operation by state, an approved retry after the proposal
deadline was denied and left the operation parked, and no path released the
hold. The proposal deadline, already the minimum of the approval timeout, the
capability expiry and the governed intent expiry, is the only clock that
governs a parked operation, because a bound nonce is verified against the
proposal's creation time rather than its own lifetime.

The retained proposal now names that deadline on the operation. The store
contract excludes a parked operation from a recovery page only while its
deadline has not elapsed; the SQLite page draws first from every active state
and only then, if the page has room, from parked operations whose deadline
elapsed, decoded and checked in order, so a live parked operation can neither
occupy nor starve a page and no schema or store protocol changed. The startup
sweep compensates an expired parked operation through the existing
pre-dispatch compensation, which reverses the executable hold and any owned
preflight hold before the terminal projection; a live parked operation in a
page still fails the sweep closed. The compensation proof had enumerated the
pre-dispatch states by hand and omitted the parked state, so the state machine
accepted the transition while the proof refused it; the proof now defers to
the state's own pre-dispatch predicate. A retry that reaches the kernel after the
deadline retires the operation in process before its denial, so the retained
hold is released without waiting for a restart. The public
recoverable-admission sweep remains the primitive a timer drives between
restarts.

Four regressions run the kernel against SQLite with a two-second proposal
timeout, wide enough that minting the proposal cannot itself straddle the
deadline. Under the strict nonce profile an expired parked operation survives
the reopen untouched, is retired by the recoverable sweep alone with its hold
released and a fresh request parks again; an expired retry retires it in
process and replays the denial; a live parked operation survives startup
recovery and completes once approved. Without the nonce profile the collector
suite retires an expired pending approval at startup, after which the
collector cannot deliver and the retry denies. The store's recovery-page test
now shows the parked operation excluded one millisecond before its deadline
and included at it. CI names both extended inventories.

Qualifying the sweep exposed a clock seam in the previous milestone. A bound
nonce is verified at its proposal's creation time, which the budget authority
stamps from its own clock, while the admission clock had already found the
nonce live; the two can straddle a second, and a nonce that expired between
them parked an operation whose approved retry could never execute. The kernel
now refuses to park a nonce that has expired by the proposal's own creation
time, so the retained issuance and the proposal never disagree, and the
regression that approves after the issuance lifetime uses a window wide enough
for the admission itself.

The sidecar composition remains open.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. The exact
inventory steps ran from the actual workflow YAML with one test thread; the two
extended inventories ran three further times each after the timing of the new
regressions was widened, all green.

| Boundary | Result |
| --- | --- |
| Exact kernel cumulative approval under strict preflight | Eight passed, zero failed or ignored |
| Exact kernel collector restart lifecycle | Ten passed, zero failed or ignored |
| Exact kernel remote delivery | Eleven passed, zero failed or ignored |
| Exact kernel nonce participant lifecycle | 15 passed, zero failed or ignored |
| Full default and post-quantum kernel library | 1,200 and 1,236 passed, zero failed or ignored |
| Kernel integration test binaries | All passed, zero failed |
| Full SQLite library, eight test threads | 1,208 passed, zero failed, three existing ignored |
| Kernel and SQLite Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene, proof inventory and security CI contract | Passed |

The regenerated proof inventory matches 58 rows and 166 artifacts, without
establishing new proof coverage. No wire schema, store schema or generated SDK
binding changed.

## Sidecar reservations as durable operations

The sidecar's mediated authorization reserves a budget hold for a tool that
a caller executes elsewhere and settles it later by the nonce it minted. Under
the strict nonce profile with durable admission that reservation was denied
outright, because the operation-owned participant reserved and captured only
inside this kernel while the legacy reservation kept a hold open for a tool
the kernel never dispatched, in a separate budget store, closed only by a
reaper or a reconcile the operation could not receive.

The composition adds no admission state and no store schema. A caller
reservation is the execution's first half: the strict preflight issues the
operation-bound nonce and reverses its own hold as before, then the execution
request presenting that nonce registers its provider attempt against a
caller-report transport, acquires the executable hold, decides cumulative
approval and reserves the nonce, and stops in `ReadyToDispatch` instead of
preparing capture. The reserving receipt carries the retained nonce and names
the hold reserved and no tool dispatched; a legacy hold stamp is never applied
to a retained nonce. The reconcile is the same operation's second half: the
kernel resolves the reserved operation from the request the nonce binds,
rebuilds the execution request from the retained original, refuses arguments
that do not hash to the retained action, and resumes the evaluation with the
caller's report standing in for the tool server, so the return is recorded,
evaluated, receipted and replayed exactly as an in-kernel dispatch. An
in-kernel evaluation of a caller-reserved operation denies on the transport
binding, and a kernel dispatch never resolves a tool server for a
reservation.

Startup recovery treats a caller reservation whose reserved nonce is still
live as waiting, exactly as it treats a live issuance, and compensates it once
the nonce expires; the public recoverable-admission sweep remains the timer
primitive. The combined capture is issued under the owner that resumes the
operation rather than the owner that authorized its hold, so a reservation
outlives a restart. The sidecar installs the authority's own budget store on
its mediation kernel under durable admission, names the mediation policy by a
canonical digest, accepts a presented nonce on the mediated route only as the
approved retry of a durable reservation, and reconciles through the kernel's
caller-report entry; the legacy in-memory reservation is unchanged for a
sidecar without durable admission.

Seven regressions run the kernel against SQLite: a reservation holds the
budget until the report settles, replays the completed receipt and never
touches the kernel's own server; a report for other arguments is refused and
keeps the reservation; a nonce of an unreserved operation cannot reconcile; a
kernel dispatch cannot resume a reservation; a restart keeps a live
reservation and the next process settles it; an expired reservation is
compensated by startup recovery with its hold released; and a second request
under the shared grant cannot preflight while the reservation is open. The
sidecar suite drives the mediated route under durable admission through
reserve, settle, replay and a refused report. CI names the new inventory.
The reservation finish and the non-durable invocation capture moved into
their own modules beside the evaluation core, which stays under its hygiene
cap.

A monetary caller reservation needs the qualified payment adapter every
durable monetary admission requires, and its realized cost settles through
the payment participant; the delegated sibling-share bookkeeping of the legacy
reservation is not retained by the durable operation and remains open, as do
provider-signed delivery receipts.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory. The exact
inventory steps ran from the actual workflow YAML with one test thread.

| Boundary | Result |
| --- | --- |
| Exact kernel caller execution | Seven passed, zero failed or ignored |
| Exact kernel cumulative approval under strict preflight | Eight passed, zero failed or ignored |
| Exact kernel remote delivery | Eleven passed, zero failed or ignored |
| Exact kernel nonce participant lifecycle | 15 passed, zero failed or ignored |
| Exact kernel collector restart lifecycle | Ten passed, zero failed or ignored |
| Full default and post-quantum kernel library | 1,200 and 1,236 passed, zero failed or ignored |
| Kernel integration test binaries | All passed, zero failed |
| Full SQLite library, eight test threads | 1,208 passed, zero failed, three existing ignored |
| Sidecar library and integration suites | 209 passed, zero failed or ignored |
| Conformance support targets | Compiled |
| Kernel, SQLite and sidecar Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene, proof inventory and security CI contract | Passed |

The regenerated proof inventory grew by the two protocol harnesses recorded in
the hosted triage above. No wire schema, store schema or generated SDK binding
changed.

## Dedicated admin credentials at every hosted-MCP launch

The integration restored the admin-credential contract as a workspace gate,
but the launch surface it describes never reached this branch: the gate
demanded a dedicated `--admin-token` at every shipped hosted-MCP launch, a
docker entrypoint that refuses to start without three distinct bearer
credentials, and a conformance runner that validates its credentials before
any effect, while the tree carried none of them. The original security source
held that surface, so this milestone ports it and closes the last hole the
gate could not see, the docker image command that launched the edge from an
unaudited shell string.

Every shipped launch now presents its admin credential. Four documentation
pages and the operations runbook show the flag beside the session and control
credentials; the four example launchers and the SDK publication script pass
it from their environment with defaults that never collide with the session or
control defaults, and every trust service in those examples takes its own
control credential instead of the client token. The docker demo starts through
an entrypoint that requires three explicit, distinct bearer credentials and
hands them to the edge through its environment, never through argv; the image
no longer carries a launch string.

The edge itself carried the conflation the gate exists to prevent: with no
admin token configured it promoted the session token to the admin role, so
every session holder could rotate the authority, revoke capabilities, drain
and shut down sessions. That promotion is gone. Every bearer-authenticated
edge now refuses to launch without a dedicated admin credential or with one
that repeats the session token, and under a control URL it also requires a
session credential and refuses a control credential that repeats a static
session or admin token, which is what the systemd unit states. The
hosted-MCP integration suite had relied on that promotion: its session-only
launchers named no admin credential and its tests read the admin routes with
the session token. Those launchers now carry a dedicated admin credential,
the control-backed launcher carries all three roles, and every admin-route
call in the suite presents the admin credential. Every client that reads a session's trust through the admin
routes presents the admin credential, and every receipt query presents the
trust service's control credential, so the examples run against the
separated defaults instead of relying on one token serving every role.

The conformance runner validates both credentials before it touches the
results directory or spawns a process, refuses an empty, padded, control-laden
or reused token, and delivers the admin credential to the child edge as the
last link of one environment chain while stripping inherited variants. Its
two credential preflight regressions prove no effect precedes the refusal and
that distinct credentials recover.

The workspace gate and its self-test pass with the inventories unchanged; the
gate's own inventory gained the progressive tutorial, which the docs
reorganization had moved out of its view. The remote edge suite carries the
bearer-role regression, the buyer service's unit tests exercise the admin
credential on the trust route, and the hosted-MCP integration suite ran
against the enforcing edge.

The credential contract is closed; the launch surface behind it is not. On
this branch `serve-http` requires a signed manifest and a signed native-launch
policy with an independently pinned signer, which the conformance runner
provisions through `chio security provision-native-mcp-demo` and the systemd
unit and operations runbook document. The progressive tutorial, the example
launchers, the SDK publication script and the docker demo pass neither, so
those launches stop at argument parsing before any credential check runs; the
SDK publication script reproduced that locally, and the demo image itself did
not build on this branch for a reason unrelated to credentials, closed in the
next section. The original security source
carried a provisioned docker demo (an init service that provisions the demo
at migration stage Disabled and publishes its public artifacts, an entrypoint
that binds them, a TLS-terminated trust service) that was never integrated;
this branch's edge also refuses a local authority seed beside a control URL,
so that design needs adaptation rather than a copy. Provisioned launches
across the whole shipped launch surface are the next milestone.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022`, disabled core dumps and the dedicated target directory; Python
3.13.13 and Node 24.16.0 ran the example services and their tests; Docker
29.5.3 with Compose 5.1.4 built the demo image.

| Boundary | Result |
| --- | --- |
| MCP admin credential contract gate and its self-test | Passed, 56 credential mutations rejected |
| Remote MCP edge library | 53 passed, zero failed or ignored |
| Hosted-MCP integration suite, `mcp_serve_http` | 42 passed, zero failed, one existing ignored |
| Hosted-MCP auth server suite, `mcp_auth_server` | Five passed, zero failed or ignored |
| Conformance runner crate, every test binary | 73 passed, zero failed or ignored |
| Docker demo entrypoint unit tests | Three passed |
| Agent commerce buyer service unit tests | Six passed |
| SDK publication examples end to end | Failed before the credential check: `serve-http` requires `--cage-policy` and `--cage-policy-signer` |
| Conformance, remote MCP and CLI Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene, review slices and workspace structural gates | Passed |

## Embedded sources in Docker build contexts

The hosted-MCP demo image did not build on this branch. The CLI now compiles
the trace validator, which embeds three TLA models through `include_str!`,
and the conformance runner, which embeds an observer key fixture from the
same tree, while the CLI image stage copied every path package and nothing
under `formal/tla`. The Docker-context gate introduced earlier in this
integration derives each stage's required directories from `cargo metadata`
and could not see a file that a compiled source embeds from outside its
package. The sidecar image under `deploy/sidecar` carried the same defect on
main for the finding schemas the control plane embeds from `spec/`.

The gate now derives both requirements. For every stage it still requires
the directory of every path package the workspace resolves, because Cargo
loads every member manifest before it builds anything. It additionally scans
the compiled sources of the packages the stage names with `cargo build -p`,
or of every member when it names none, for `include!`, `include_str!` and
`include_bytes!`, and requires every embedded file outside its package to be
covered by the stage's copies. Compiled means what an image build compiles:
the build script and `src`, without modules whose `cfg` cannot hold in a
Linux image build with no test harness, and without inline modules under
such a `cfg`. Module declarations are resolved through `#[path]` attributes
and the conventional layout, and `cfg` expressions are evaluated with `test`,
`windows` and non-Linux targets false and undecidable predicates such as
features true, so the check stays conservative. The CLI image stage copies
`formal/tla` and the sidecar image copies `spec`; no other tracked stage
lacked an embedded file.

With every crate compiling, the CLI image still failed at the final link:
the Alpine musl target links statically and the builder stage installed only
the shared OpenSSL development package, so the WebAuthn dependency's
`-lssl` and `-lcrypto` had no archive to resolve against. Main carries the
same stage, and no hosted lane builds it. The builder now installs the
static OpenSSL archive and pins static linkage the way the sidecar image
already does, and the runtime stage no longer installs shared OpenSSL
libraries the binary never loads.

The gate's self-test covers the stage parser with continued `RUN` lines and
package selection, the `cfg` evaluator, module resolution on a scratch
package with test-only, path-declared, nested and inline modules, ancestor
coverage of embedded files, and the two real stages: the CLI image without
the TLA tree fails on the trace validator's model, and the TEE image, which
never compiles the finding crates, requires no embedded file.

Local verification used Rust 1.94.1 on Linux aarch64, Python 3.13.13, Docker
29.5.3 and Compose 5.1.4.

| Boundary | Result |
| --- | --- |
| Docker build context gate over the six tracked stages | Passed: 1,006 resolved path packages and 36 embedded files covered |
| Docker build context gate self-test | Passed |
| Hosted-MCP demo image build, `docker compose build chio-mcp-demo` | Built: every crate compiled and the binary linked statically; the image is 275 MB |

## Provisioned launches across the shipped launch surface

On this branch the edge launches only the wrapped command its signed
native-launch policy binds, and `serve-http` and `serve` refuse to parse
without that policy and its independently pinned signer. The conformance
runner and the systemd unit carried them; the progressive tutorial, the
example launchers, the SDK publication script, the CLI smoke script and the
docker demo did not, so every shipped launch stopped at argument parsing
before any credential or policy check ran, and the previous milestone's SDK
run reproduced that. This milestone makes every shipped launch provision a
signed manifest and a signed native-launch policy for its exact command and
launch through them.

The provisioner, `chio security provision-native-mcp-demo`, took a reviewed
`tools/list` fixture that existed for no shipped server. It now discovers the
reviewed surface from the target itself: with `--discover-tools` it spawns
the exact target once in its working directory, with every Chio credential
stripped from the environment, completes the MCP initialize handshake under
a bounded deadline and output size, records the advertised `tools/list` as
`reviewed-tools.json`, and tears the target down before it returns. The
fixture and discovery are exclusive and one is required; the report names
which produced the surface; an idempotent rerun discovers again and refuses
a surface that changed. Discovering the conformance mock server yields
byte-for-byte the reviewed fixture the conformance lane pins.

A shared shell helper, `scripts/lib/provision-mcp-launch.sh`, provisions a
launch for the invoking user and exports the four binding flags and the
canonical command, so a launcher splices them and the launched command
equals the bound one by construction. It resolves a Python target through
the interpreter itself, because version-manager shims on PATH canonicalize
to the manager rather than the interpreter the edge binds; it canonicalizes
the working directory; it refuses a root execution identity; and it replaces
a prior provision it made, because every provision binds the digest of the
chio executable that made it and a rebuilt binary invalidates the old one.
The commerce provider launcher, the incident and web3 network launchers, the
SDK publication script and the CLI smoke script's stdio launch provision
through it; the incident and web3 launchers also wrap `python3` instead of a
bare `python`. The docker demo entrypoint provisions at every container start
into a private tmpfs, as the unprivileged edge user, and launches only the
provisioned command. The tutorial, the operator runbook pages, the sidecar
build guide and the identity federation guide show the provisioning step and
the four flags; the federation guide now wraps the repository's mock server
instead of a file that never existed.

Running the launches surfaced three more seams the source never crossed.
Under a control URL the edge also requires the workload token the trust
service accepts only for capability issuance, distinct from every other
bearer, and an exact pin of the trust service's current capability authority
key; every hosted launcher now starts its trust service with the workload
token, reads the authority key from the service's authority route once it is
healthy, and passes both, the docker demo through the trust image's command,
the compose environment and the entrypoint, which validates the workload
token as a fourth distinct credential and keeps it off argv. The edge refuses
a wrapped executable that other users can write, which is how a
version-managed developer interpreter is installed, so the helper resolves a
Python target to the first interpreter among the invoking one and the system
ones that is a regular executable nobody else can write. A local receipt
read now needs a tenant or an explicit administrative scope, which the CLI
smoke script's receipt listing states. A stdio edge under durable admission
needs the session database, which the smoke script's launch now passes. An
edge that keeps durable session state needs a dedicated resume HMAC keyring,
so the helper writes a fresh private keyring per launch and every launcher
with a session database passes it. The trust service behind a hosted edge
must hold the joint admission authority, which is its own session database,
and that database replaces the separate revocation and budget databases the
launchers used to pass; every trust service in the launch surface, the docker
trust image's command and the runbook now start that way. The edge keeps
session state only under directories that nobody else can write, which a
checkout made under a permissive umask is not, so the helper provides a
private launch state directory under the user's runtime directory, or a
root-owned sticky temporary directory, and the launchers keep session
databases, resume keyrings and provisioned policies there while artifacts
keep logs. The commerce smoke's buyer service also needed its package on the
import path when started from the repository root, and its sidecar, which
trusts only the capability issuers it is told about and its own signer, now
names the control authority it pins as a trusted issuer, as the web3 example
already did for its settlement sidecar; the incident and web3 sidecars pin
the authority key the same way once their trust services are healthy.

The remote edge had checked the policy against the wrapped command lazily,
per session, so an unbound command bound its listener, passed every
readiness probe and then failed each `initialize`. It now proves at startup,
after the cheaper configuration checks, that the policy authorizes the
wrapped command, and a hosted-MCP integration test drives an edge whose
policy binds a different script and reads the refusal from its exit.

The commerce and incident network smokes now start every Chio process they
wrap, the hosted edges listen and the sidecars pin their authority, and both
then stop inside their own business flows: the commerce buyer sidecar denies
the driver's capability because it does not authorize the sidecar's
projected HTTP tool, and the incident trust service answers the second
lineage record with a server error. Neither is a launch defect; both are
example flows meeting the hardened control plane, and they are the next
milestone. The web3 network needs a local chain this host lacks.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo
resolution, `umask 022`, disabled core dumps and the dedicated target
directory; Python 3.13.13 and Node 24.16.0 ran the example services and
tests; Docker 29.5.3 with Compose 5.1.4 built the demo images.

| Boundary | Result |
| --- | --- |
| SDK publication examples, end to end against a provisioned hosted edge and trust service | Passed |
| CLI smoke script, `mcp` group, stdio edge under a provisioned policy | Passed |
| Native MCP demo provisioner suite, discovery included | Ten passed, zero failed or ignored |
| Hosted-MCP integration suite, the edge refusing an unbound wrapped command | Passed |
| Remote MCP edge library | 53 passed, zero failed or ignored |
| Docker demo entrypoint unit tests | Six passed |
| MCP admin credential contract gate and its self-test | Passed, 50 credential mutations rejected |
| Docker demo compose stack, `docker compose up` then `smoke_client.py` | Passed: the trust image starts healthy with the joint admission authority, the edge provisions at start and serves, and the smoke client's governed call returns a receipt |
| CLI and remote MCP Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene, review slices and workspace structural gates | Passed; the web3 contract parity check fails on this host's package manager cache as before |

## Example flows under the hardened control plane

With every launch provisioned, the commerce and incident network smokes
started all of their Chio processes and then failed inside their own flows.
Neither failure was a launch defect and neither was new: main failed the
same steps with a different message, because its sidecars trusted no
external issuer at all.

The commerce buyer sidecar denied the driver's first side-effect route. An
`api protect` sidecar binds every deny-by-default route to one synthetic
tool, `authorize_http_request` on server `chio_http_authority`, and
requires a capability that grants exactly that; the driver's capability
granted only its own client tools. The driver now requests that grant beside
them, as the hello and web3 examples already did. The incident sidecar
capability gained the same grant for its coordinator routes.

The incident trust service answered the second lineage record with a server
error. The example delegates capabilities client-side and signed a body that
carried empty `constraints`, `resource_grants`, `prompt_grants` and
`attenuations` collections and no schema envelope, while Chio signs the
canonical JSON of the schema-bearing signing body with every empty
collection and absent optional field left out; the trust service verified
the delegated token's signature, failed, and the handler mapped that client
conflict to 500. The example now prunes empty collections from the bytes it
signs and signs the `chio.capability.v1` envelope, which also lets its
offline reviewer verify the trust-service-issued root, and the lineage
handler answers a store conflict with 409 and a missing parent with 404, as
its billing sibling already did.

The last delegated capability to fail carried budget limits. Both examples
named them with camelCase keys, `maxInvocations`, `maxCostPerInvocation` and
`maxTotalCost`, while a Chio tool grant serializes `max_invocations`,
`max_cost_per_invocation` and `max_total_cost` and its deserializer ignores
unknown keys, so the trust service had been issuing every example capability
without the budget limits the examples believed they set, and a client-built
token that carried them could never match Chio's canonical bytes. The
examples now use the grant's field names, so their limits bind.

Both examples also charged budgets by hand through `/v1/budgets/charge`, a
route that exists on neither main nor this branch; the commerce example hid
the missing route behind a broad exception handler and reported success
without ever charging, and the incident executor failed on it. Under the
joint admission authority the trust service refuses every budget mutation
that no admission binds, so a client cannot charge a budget by hand at all:
the kernel of the edge the tool is invoked through charges it during
admission. The incident executor no longer charges by hand and records that
the admission authority enforces its budget, and both clients drop the
charge method that could never succeed.

The `api protect` command accepted `--control-authority-public-key` and
ignored it; only `CHIO_TRUSTED_ISSUER_KEY` populated the sidecar's trusted
issuers, so the launchers that pinned the authority key still refused every
capability that authority issued. The pinned authority is now a trusted
issuer, with a unit test over the merge, and the buyer launcher no longer
needs a second setting.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo
resolution, `umask 022` and the dedicated target directory; the example
services ran under `uv` with Python 3.11 environments.

| Boundary | Result |
| --- | --- |
| Commerce network smoke, end to end through the provisioned edge, trust service and buyer sidecar | Passed |
| Incident network smoke, end to end through four provisioned edges, two sidecars and the trust service | Passed |
| Sidecar trusted issuer merge unit test | Passed |
| Control plane library check after the lineage handler change | Passed |
| CLI and control plane Clippy, all targets, warnings denied | Passed |
| Formatting and the MCP admin credential contract gate | Passed |

## Security preflight for the confined runtime

The confined reference runtime needs a host, credentials, signed launch
material and durable stores that the edge will accept, and until now the
first place those were checked was the edge's own startup, one refusal at a
time. `chio security preflight` proves them before the launch and exits with
the worst finding, so a supervisor gates the start on it. It is built on
the doctor framework: every check is one probe with a severity and a
registry code, the report renders as text or as the doctor JSON envelope,
and the exit code follows the worst severity, like `chio doctor`.

The platform probe measures what the cage depends on: Linux x86_64, kernel
6.7 or newer, a Landlock ABI at or above the cage's minimum, seccomp, the
no-new-privileges flag, pid file descriptors, `close_range`, `execveat`
with an empty path, sealed memory files, `openat2` resolve flags, mount
identifiers from `statx`, and the descriptor limit. The facts come from a
source the probe is built over, so the verdict logic is tested with fixed
facts and only the host source carries the system calls, each of which is
a query with no side effect. The bearer-role probe reads the four
credential variables the launch reads and reports padding and reuse the
way the edge refuses them; a role that is not set is not a defect. The
native-launch probe loads the signed manifest and the signed native-launch
policy exactly the way the edge does, against the wrapped command given
after `--`, and reports how the policy authorizes it: refused, authorized at
migration stage Disabled, or cage-required. The durable-store probe opens
every store the global options name read-only and runs SQLite's quick
check, refusing symlinks and damaged files, while a store not created yet
is reported and not failed. A host that cannot enforce the cage, or
material that authorizes without confining, is a warning by default and an
error under `--require-enforcement`, so a developer host provisioning at
stage Disabled and a production supervisor share one command.

Local verification used Rust 1.94.1 on Linux aarch64 (kernel 6.17,
Landlock ABI 7), offline Cargo resolution, `umask 022` and the dedicated
target directory.

| Boundary | Result |
| --- | --- |
| Preflight probe unit tests: platform verdicts over fixed facts, host facts, bearer roles, durable stores | Ten passed, zero failed or ignored |
| Preflight integration suite: a provisioned demo passes without enforcement and fails with it, an unbound wrapped command is refused, reused bearer roles fail | Three passed, zero failed or ignored |
| Host preflight over a discovered conformance demo, advisory | Exit 0: platform warns that only the x86_64 prerequisite is missing, four bearer roles distinct, launch authorized at migration stage Disabled, stores not created yet |
| Host preflight with `--require-enforcement` | Exit 1: the platform and the launch material are reported as errors, as a supervisor must see |
| CLI Clippy, all targets, warnings denied | Passed |
| Formatting, file hygiene and the MCP admin credential contract gate | Passed |

## Supervision package for the reference runtime

The confined runtime has had a preflight since the previous section, but
nothing in the tree ran it: the two reference units under the release
documentation predated the joint admission authority, put every bearer in
an environment file, named a placeholder upstream binary, and reported
readiness the moment the process forked. The supervision package under
`deploy/reference-runtime/` replaces them with units that a manager can
trust, and a structural gate that keeps the units, the binary and the
package agreeing.

`chio security supervise` is the main process of every unit. It reads each
secret from the manager's credentials directory (`LoadCredential=`), so no
bearer sits in an environment file or in an argument list: a credential
must be a regular file readable by its owner alone, at most sixteen
kibibytes of UTF-8; exactly one trailing newline is removed and any other
padding or control character refuses the launch, as does a variable that
is bound twice or already present in the environment. With `--exec` the
supervisor delivers the credentials and replaces itself with the service,
which is how `ExecStartPre=` runs the preflight under the same roles the
edge will see. Otherwise it spawns the service, watches readiness (a GET
answering with a success status, optionally with a bearer taken from a
delivered credential, or a Unix socket accepting a connection) against a
deadline while also watching an early exit and a stop signal, reports
`READY=1` and a status line over the notify socket, forwards SIGTERM,
SIGINT and SIGHUP, grants a bounded drain before SIGKILL, and ends with the
service's own exit status, re-raising the signal that ended the service so
the manager records the same outcome it would have seen from the service.
A service that ends before it is ready fails the unit even when it exits
zero; a readiness timeout stops the service and fails the unit.

The units cover what has a complete production path: trust-control on the
joint admission authority (receipt, authority and session stores; no seed
file, because the capability authority keeps its key in the authority
database), the remote MCP edge under a signed native-launch policy with
four distinct bearer roles and the resume keyring delivered as credentials,
and the key-log witness and audit daemons of the keyring composition as
template instances whose seeds arrive at the fixed credentials path their
configs name. Every unit is `Type=notify` with a readiness probe, runs as
its own account from `sysusers.d`, keeps state and runtime directories at
mode 0700, and carries the same hardening baseline: no new privileges,
strict system protection with `/etc/chio` read-only, private devices and
temporary directories, restricted namespaces, address families and
personality, an empty capability set, no core dumps, native system call
architecture, and memory ceilings. The edge unit requires trust-control,
runs the preflight with `--require-enforcement` against exactly the
command it then launches, polls the admin health route with the delivered
admin bearer, and keeps `KillMode=mixed` so the wrapped server outlives the
edge's drain. The tmpfiles declaration keeps credential sources root-only
and every configuration directory readable by its service account alone.

The structural gate is a CLI integration test that parses every unit and
walks each `Exec*` command against the built binary's help at every level,
recursing through `--` into the supervised command: an unknown subcommand,
a flag the binary does not accept, or a wrapped program the package does
not install fails the build. It also requires that the credentials the
manager loads are exactly the ones the service consumes, that every
environment reference is declared in the unit's template and nothing else
is, that accounts exist, that dependencies name units in the package, that
templates vary by instance, that the hardening baseline and stop timing
are present, that the edge preflight names the same launch material and
wrapped command as the launch, that the trust preflight names the stores
the service opens, and that the keylog example configs agree with the
units on socket, state, seed and witness paths. The MCP admin credential
gate now pins the edge unit's credential declarations and checks that every
bearer role in the unit is bound to its own credential file; its self-test
grew a mutation that delivers the session credential as the admin role.

Two daemons are deliberately not supervised here, and the package README
says so: the secret broker performs a production capability handshake with
its admission authority at startup while the tree carries only a test
handler for that authority, and the active-response authority's only
client is not wired into any binary. Both pin their own and their peer's
process id inside a canonical deployment config whose digest is baked into
a read-only store, so their launcher must fork both children, learn the
ids, write the configs and build the store before either continues; that
launcher lands with the authority host. The keyring README asks for the
five key-log services under separate accounts, but the witness binds its
socket at mode 0600, which admits only its own account; the package runs
them under one account and this ledger records the mismatch.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo
resolution, `umask 022` and the dedicated target directory.

| Boundary | Result |
| --- | --- |
| Supervisor unit tests: credential parsing, delivery and refusal; notify messages over path and abstract sockets; socket and HTTP readiness; exit status, early exit, readiness timeout and readiness reporting | Thirteen passed, zero failed or ignored |
| Supervise integration suite: exec delivers only the bound credential, padded, shadowed and exposed credentials refuse the launch, the service exit code is preserved, readiness reaches the manager and SIGTERM ends the supervisor by SIGTERM, a service ignoring SIGTERM is killed after the grace, a service that never becomes ready fails the unit | Six passed, zero failed or ignored |
| Structural gate over the package against the built binary: every unit's commands and flags, credentials, environment references, accounts, dependencies, hardening and keylog examples; the edge preflight against its launch; the trust preflight against its stores; the help parser | Four passed, zero failed or ignored |
| `systemd-analyze verify` over the four units on the host | Every unit parsed; the only findings are that `/usr/local/bin/chio` is not installed on this host |
| Launch material under root-only ownership: the C1 evidence copied to a mode 0500 directory with mode 0400 files, then the host preflight | The signed manifest, the policy and the migration ledger load read-only; the launch reports as before |
| MCP admin credential contract gate and its self-test | Passed; 51 credential mutations rejected, including the session credential delivered as the admin role |
| CLI Clippy, all targets, warnings denied | Passed |
| Formatting, Rust file hygiene, review slices | Passed |

## Confined reference tools and the enforcing provisioner

The supervision package could start an edge, but nothing in the tree gave
that edge a wrapped server the cage could hold, and the only provisioner
wrote material at migration stage Disabled, which authorizes a launch
without confining it. This milestone adds both halves: three MCP servers
built to run inside the cage, and a provisioner that binds them at an
enforcing stage.

`chio-reference-tools` carries a minimal MCP server core (one JSON-RPC
object per line, bounded lines, no environment, no network, no threads, so
the closed `native_minimal_v1` syscall profile is enough) and three tools:
a repository reader that resolves every path inside its root, refuses
`..`, absolute paths and symlinks that leave it, and stops at 64 distinct
files, 4 MiB per session and 256 KiB per read; an artifact writer that
replaces the content of one file that exists before it starts, never
creating, renaming or removing anything, so the exact-file grant is the
whole write surface; and a digest tool that needs no grant at all and is
the control for the other two. Each tool takes exactly the one flag its
launch policy binds. Built static with an explicit target, the tools carry
no interpreter and no shared object.

`chio security provision-reference-runtime` shares its engine with the demo
provisioner through a provisioning profile: the demo keeps Disabled stage,
no grants and the Chio executable as its pinned helper, and its report is
unchanged; the reference profile takes a static position-independent
`chio-cage-init`, the target's digest, argument list and working directory,
read and write grants that become both the manifest's permissions and the
policy's operator ceilings, runtime files for a dynamically linked target,
and a migration ledger promoted through Shadow to the requested stage with
one signed transition per step, each bound to the same launch contract and
manifest as the genesis. The policy factory now validates that the
manifest's grants equal the ceilings and that runtime files are declared
read paths, and its stage, ceilings, runtime files and receipt naming come
from the profile. A rerun rebuilds every transition from the signers and
the contract and compares bytes, verifies the ledger head at the profile's
generation, and validates the policy structurally at enforcing stages: the
signature, the bound server, the stage, the launch contract and the ledger
it names, without composing the launch, which retains the helper and the
target on the enforcing host and belongs to the edge and the preflight.
Before binding, the provisioner reads the ELF headers the way the cage
does: the helper must be a static position-independent executable, and a
target must be static or declare its interpreter and every shared object
as runtime files.

The cage's architecture resolver accepts only x86_64 at run time, so on
this aarch64 host the enforced material can be produced, revalidated and
checked by the preflight up to the point where the cage refuses the
architecture; the launch itself is the x86_64 lane's evidence. The
aarch64 GNU and musl toolchains produce static fixed-address images rather
than static position-independent ones, and the musl helper build cannot
link here, so the helper the provisioner tests bind is a synthetic image
with the exact ELF shape the cage requires.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo
resolution, `umask 022` and the dedicated target directory.

| Boundary | Result |
| --- | --- |
| Reference tools server core: handshake, listing, calls, refusals, invalid params, unknown methods, malformed and oversized lines | Three passed, zero failed or ignored |
| Reference tools over stdio: the reader lists, reads and stats inside its root, refuses every way out of it, stops at its session budget; the writer replaces one pre-created file in place and needs it before starting; the digest tool computes without any grant and refuses arguments | Six passed, zero failed or ignored |
| Static builds with an explicit target: the three tools on aarch64 GNU and aarch64 musl | Static executables, no interpreter, no shared object, 1064424 bytes each on GNU; fixed-address rather than position-independent on this architecture |
| Static build of the cage helper on this host | aarch64 GNU produces a static fixed-address image the cage would refuse as a helper; aarch64 musl cannot link its C dependency here; the x86_64 lane produces the static position-independent helper |
| ELF linkage inspector unit tests: static and position-independent images, a dynamic image's interpreter and shared objects, malformed images, the test executable itself | Four passed, zero failed or ignored |
| Reference runtime provisioner suite: an Enforced provision binds the helper, the grants and a ledger promoted through Shadow with three signed transitions, reruns byte-identically and detects a tampered promotion; a Shadow provision authorizes without containment and the preflight reports it as legacy; the preflight treats Enforced material as cage-required; a dynamic target needs its runtime files declared as read paths and a fixed-address helper is refused; the demo provisioner keeps its Disabled-stage report without the new fields | Five passed, zero failed or ignored |
| Demo provisioner and preflight suites as regressions over the shared engine | Ten and three passed, zero failed or ignored |
| Supervision package structural gate after the environment template change | Four passed, zero failed or ignored |
| Host evidence: the static reader provisioned at Enforced with its tools discovered live, then the enforcing preflight | Three tools discovered, ledger at Enforced generation 2 with three transition digests, nineteen artifacts; the preflight exits 1 with the native-launch probe refused at cage admission for an unsupported seccomp architecture |
| CLI and tools Clippy, all targets, warnings denied | Passed |
| Formatting, Rust file hygiene, review slices, no em dashes | Passed |

## The reference swarm

The reference runtime had tools the cage could hold and an edge that could
launch them, but nothing exercised them the way a swarm would, and the
swarm authority crate had only its offline example. `examples/reference-swarm`
is an orchestrator and two workers driving the three reference tools through
three edges, one per tool, with the swarm authority verifying the delegation
before and after the run and every tool call leaving a receipt in
trust-control.

The orchestrator generates a key for the run, signs a task graph that
delegates a narrower scope to each worker (the reader worker may list, read
and stat inside one repository, the writer worker may write, read and stat
one artifact, the orchestrator digests results through an edge whose policy
grants `sha256` alone), and binds each delegation to an attenuation witness
computed from the real scopes, a route plan to the worker's edge, an
allocation from one budget pool and a single-use continuation token over the
signed graph. `verify_swarm_authority_bundle` admits the bundle before any
worker starts; after the run the pool is released for the completed worker
with `release_swarm_budget_fanin`, the terminal receipt is signed over a
digest of the scenario verdicts, and the bundle is verified again, which
fails as it must because the reader's task was revoked mid-run.

Seven scenarios cover what the runtime must allow or refuse, each observed
through the edge's answer, the kernel's `tool_denied` event, the
trust-control receipts and the authority's verdicts: a successful list,
read, write, read-back and digest with receipts for every capability; a
path outside the reader's root refused by the tool and a forbidden system
file denied by the edge's forbidden-path guard before the tool sees it; a
tool outside the digest edge's grant denied by the edge while no
attenuation witness exists for a worker scope wider than the orchestrator's;
two workers sending all eight `stat` attempts concurrently against grants
with `max_invocations: 6`, requiring the kernel to deny two overruns per
grant without local short-circuiting or retrying authority errors; a write carrying an AWS credential pattern
denied by the edge's secret-leak guard with the artifact untouched; the
reader edge stopped and started again mid-session with the worker continuing
by session id from the session store and keyring; and a capability revoked
through the edge's admin route mid-run, after which the edge denies the next
call and the bundle no longer verifies for that task. The writer's tools
were renamed to the vocabulary the kernel's guards read (`write_file`,
`read_file` and `stat` with `path`, writes with `content`), each call naming
the one artifact, so the guards see exactly what the tool will do. Network
denial is the cage's seccomp filter with no edge-level lever, and the
example says so.

The smoke starts trust-control and the three edges, each provisioned under a
signed native-launch policy through the shared launch helper, runs the
orchestrator with a restart hook that stops and relaunches the reader edge,
exports the receipts with `chio evidence export` and verifies the package
offline with `chio evidence verify`. These launches use the signed `Disabled`
demo profile on every architecture. An x86_64 host does not automatically
make them confined. The fixture is not Enforced-profile qualification.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo
resolution, `umask 022` and the dedicated target directory.

Two findings surfaced in the joint admission authority under concurrency.
First, while the two workers ran against their edges at the same
time, calls were refused with `trusted admission operation time regressed`:
the admission operation store keeps one trusted-time high-water mark per
store (`crates/platform/chio-store-sqlite/src/admission_operation_store/schema.rs`,
`verify_trusted_time`) and compares it against a timestamp the kernel
sampled before the write transaction
(`crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs`,
`refresh_trusted_time`, the requested time clamped to the wall clock). A
commit whose sample was overtaken by another writer's later sample is
refused as a regression although no clock regressed. The refusals appeared
in each edge's own log across the steps of one request (dispatch commit,
admission, capture boundary) and only while both workers were active; the
original scenario retried those failures. The revised scenario fails on an
authority error and runs concurrency before crash/restart. The implementation
now separates sampled decision time from transaction-observed authority time
with admission schema 17 and v2 commit preimages. Old hashes and rollback
anchors remain intact; per-operation ordering, bounded clock skew and actual
authority-clock rollback rejection remain enforced. Live leases, nonces,
approval windows and assignment evidence cannot be revived by a delayed
decision timestamp. The signed terminal regression inserts another operation's
later decision before the terminal write and checks byte-exact retention.
The seven-scenario live integration rerun passed without clock-error retries.
Its joint authority retained 477 v2 commits for 29 operations, including 41
adjacent decision-timestamp reversals across operations, with no authority-clock
or per-operation timestamp regressions. All operations ended completed (23)
or compensated before dispatch (6). The CLI maps the trust service's
`--session-db` to this joint authority; the separate `--authority-db` contains
capability-authority state and is not the admission commit log.
Blind clamping or retrying under a new request identity is not qualification.

Second, recovery reported `retained executable hold is absent from the budget
authority`, after which restore deleted the session. This did not establish
that the SQLite authority lacked the hold: `RemoteBudgetStore` inherited an
unsupported lookup that returned `Ok(None)`. The implementation now uses a
fenced internal authority lookup, preserves the complete retained hold
projection, and rejects unsupported/unavailable or malformed responses.
The budget trait default now returns an error for unsupported lookup.
Authenticated session records survive restoration errors; startup fails
closed. Incompatible runtime/auth configurations leave records inactive
without deleting them. Actual authoritative absence still fails recovery;
it is not silently interpreted as reversal.

The recovery scanner also excludes verified live nonce issuances and live
caller-report reservations before filling its bounded page. Otherwise a page
of quiescent work can hide later compensation or expired approval work.

The swarm task graph still lacks runtime binding to the edge-issued
capability identities. Per-grant invocation ceilings do not prove shared
task-pool enforcement. The revised smoke passed all seven integration scenarios
at `examples/reference-swarm/artifacts/live/20260907T135018Z`. Its concurrent
workers each received exactly six allows and two budget denials; the fixture
also verifies receipt signatures, unique request and receipt identities, exact
capability/server binding, and the kernel's specific budget-denial reason.
The evidence package verified 30 tool receipts and nine capability-lineage
records. All 30 receipts remain uncheckpointed, with no inclusion proofs;
this is not Merkle/transparency or confinement qualification. Package consumers,
qualified Linux confinement, enterprise capture,
dependency audits and the observed operator pilot remain separate gates.

| Local verification | Status |
|---|---|
| Remote hold projection, authoritative absence, fenced/error/malformed response groups | 3 passed |
| MCP unit suite, including byte-preserving restore failure | 54 passed, none ignored |
| Control-plane unit suite plus added real SQLite hold-route auth/fence test | 983 passed plus 1 passed, none ignored |
| SQLite caller, cumulative approval, lifecycle and remote-delivery suites | 41 passed, none ignored |
| Recovery-page live issuance boundary | 1 passed |
| Scheduler cleanup preserves terminal failure | 1 passed |
| Swarm budget classifier and signed receipt corroboration | 3 passed |
| Live swarm integration, including concurrent budgets and restart | 7 scenarios passed; Disabled confinement; 30 uncheckpointed receipts verified |
| Complete SQLite unit suite | 1,219 passed, 3 existing ignored tests |
| Final clock/upgrade/assignment-expiry regression filter | 21 passed, none ignored |
| Clippy, all targets of control-plane, SQLite store, MCP remote, CLI and reference-swarm | Passed with warnings denied |
| Production mount-ID module | 2 GNU host tests passed; aarch64 musl cross-check passed on Rust 1.94.1 |
| Security CI contract, review slices, MCP admin credential contract | Passed |
| Security CI contract mutation tests | Passed |
| Full musl CLI cross-check | Blocked before Chio by missing `aarch64-linux-musl-gcc` |
| Formal mirror reconciliation and full launch qualification | Open |

The broader nonce run exposed two fixture races. The live-issuance expiry
test now uses the kernel/store scoped clock and checks the exact expiry
boundary instead of assuming startup finishes in two seconds. The shared
fixture now waits for the receipt writer's bounded readiness barrier, as
production configuration already does. No readiness or expiry gate was
weakened. The complete four-suite rerun above includes both corrections.

Clock separation also exposed synthetic fixtures whose authority clock was
already later than the lease they expected to use, or switched backwards when
entering a worker thread. Their explicit scoped clocks now follow the intended
timeline. The equal-length divergent-history attack constructs an internally
valid v2 forgery before checking rollback rejection, so it continues to test
the external anchor rather than failing on an obsolete preimage format.
Schema-16 upgrade tests independently encode the v1 preimage, preserve the
original head and rollback anchor, reject a lagging authority clock, append v2,
and reject clock-column removal, tampering and failed partial migration.

### Swarm runtime request binding

Review of the existing runtime hook found that a valid stored swarm bundle
could accompany a request carrying a different capability, including a newly
signed token with the same ID and scope. A request could also reference a
sibling's otherwise valid witness. Three regression tests reproduced admission
or dispatch acceptance before the fix.

The hook now binds the continuation's selected task to the canonical SHA-256
of the complete signed request capability and its scope. All incoming and
outgoing witness endpoints for that task must agree, including multi-hop
delegation and fan-in returning to the root. Direct continuations must select
their own witness, and join continuations their own join receipt. The check
runs before continuation consumption and again at final dispatch revalidation.
Successful metadata retains graph, task, capability, scope and normalized
evidence-reference hashes. Removing context or binding metadata after admission
fails revalidation, including for resumable continuations. Rejected requests do
not consume a continuation; failed revalidation does not erase its reservation.

This closes a request-binding defect in `ChioRuntimeAdmissionHook`; it does not
close the reference swarm's edge integration gate. That smoke still reports
`taskCapabilityBindingEnforced: false`. The edges must install and require the
runtime path, associate real issued capabilities with verifier-owned task
evidence, and reject omission of task context at initial admission. Authoritative
task-pool accounting, session/root-transaction binding, fresh revocation updates,
checkpointed receipts and qualified confinement remain separate work. The
standalone swarm verifier remains an offline evidence verifier, not an assertion
that a live tool invocation used that evidence.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022` and the dedicated target directory. All 260 tests across
`chio-runtime-core` (183, including 55 runtime-admission tests and nine new
binding regressions), `chio-runtime` (13) and `chio-swarm-authority` (64) passed,
with none ignored. All-target Clippy for those three crates passed with warnings
denied. Formatting, Rust file hygiene, review slices, whitespace checks and the
security CI contract also passed. The full workspace, exact-head remote CI,
formal mirror reconciliation and launch qualification were not established by
this focused run.

### Required swarm deployment policy

The native kernel now has a monotonic `require_swarm_admission()` requirement,
also available through Chio YAML `kernel.require_swarm_admission: true`.
Every tool call then needs an object-valued swarm context and a runtime hook
that explicitly implements swarm authority verification and final dispatch
revalidation. Omitting metadata, clearing the hook, or replacing it with an
ordinary permissive hook cannot turn off the requirement. The built-in runtime
hook and its facade implement the contract; legacy hooks default to unsupported.
The support declaration is trusted host code, not a caller assertion or a
replacement for the signed-bundle and exact-capability verifier.

The policy compiler installs the requirement for constructed and restored
kernels. Enabled policy changes the runtime policy identity. Omitted and explicit
false values retain the ordinary policy's serialized identity; malformed values
reject at load time. Runtime admission was extracted from the large dispatch
module into `dispatch/runtime_admission.rs`, bringing the parent file below the
ordinary size limit and removing its exception.

This is the mandatory-context prerequisite, not complete live edge provisioning.
The reference smoke's integration-only and false task-binding flags remain
unchanged until its edges install the verifier with real issued capabilities,
trusted evidence, authoritative task budgets and revocation updates. No new
capability wire caveat or cross-kernel enforcement guarantee is claimed.

Local verification used Rust 1.94.1 on Linux aarch64, offline Cargo resolution,
`umask 022` and the dedicated target directory. All 2,562 executed tests passed,
with none ignored: 1,205 kernel unit tests, 987 control-plane unit tests, 108 MCP
edge unit tests, and 262 tests across runtime-core, the runtime facade and swarm
authority. Coverage includes signed denials before tool side effects, strict
policy loading and policy-hash compatibility, hook replacement and removal,
JSON-RPC context omission, and actual kernel dispatch using the built-in swarm
verifier. The valid dispatch invokes the tool once and signs the exact task and
capability binding; omission and capability substitution invoke it zero times.
All-target Clippy for those six crates passed with warnings denied. Formatting,
Rust file hygiene, review slices, Rust public-surface policy, the security CI
contract and whitespace checks passed. The local code graph was refreshed.
This run does not establish full-workspace, exact-head remote CI, formal mirror,
confinement, live reference-edge or launch qualification.

The fresh formal-mirror check still reports ten drift entries across six Rust
files for `RevocationPropagation`, `ReceiptBeforeAllow` and
`PostAdmissionDropGuard`. Their implementation/model contracts still require
semantic reconciliation. No proof-manifest hashes were blessed in this slice.

### Delivery readiness and final authorization

Formal-anchor review exposed a concrete dispatch race. Both ordinary and
nested-flow evaluation awaited remote delivery preparation after their final
authorization check. A preparation callback could observe a revoked capability
and return success, after which the kernel still invoked the tool. Two
regressions reproduced one tool invocation after revocation before the fix.

Transport preparation now runs inside the existing armed pre-dispatch readiness
guard, before payment authorization, pool claiming, credential retention and
security dispatch commitment. Final revalidation follows preparation and samples
its clock after readiness completes. Preparation forces full mutable guard and
runtime-hook revalidation even when its future returns immediately. A transport
readiness callback may check reachability but must not execute a tool or deliver
its arguments. Normal refusal follows the existing signed cleanup-denial path;
dropping the pending preparation uses the same RAII compensation as a dropped
runtime-admission wait. Both evaluation paths share the readiness helper instead
of duplicating late transport-denial cleanup.

Deterministic regressions exercise revocation, capability expiry across the wait,
runtime-authority changes in an immediately ready callback, refusal, cancellation
and successful dispatch. They inspect tool invocation counts and durable
operation disposition, not only the returned verdict. Kernel-mediated revocation
is covered separately from direct test-store mutation. Successful preparation
does not create an atomic guarantee against every later external state change;
existing dispatch/store fences and their qualification boundaries still apply.

The same review found post-payment revalidation incorrectly conditioned on the
presence of single-use dispatch credentials. Two additional regressions showed
that a payment adapter could invalidate mutable guard or runtime-hook authority
and the tool still ran when the request had no nonce, DPoP or approval token.
Both paths now force full non-consuming revalidation after an acknowledged
payment authorization, independently of credential presence. Rejection uses the
existing payment-unwind path before tool dispatch.

The wider control-plane runs also exposed three recovery fixtures whose
one-second leases expired during parallel setup. Their failed-run diagnostics
were `LeaseExpired`; isolated replay of the initial failures passed. Recovery
fixtures now share an explicit scoped-clock helper for their short setup leases,
including the clocks installed in both concurrent workers. The SQLite nonce
expiry integration test likewise expired its one-second nonce during preflight
setup on a loaded host. It now issues while the scoped clock is live and advances
to the nonce's exact expiry boundary instead of sleeping. Production lease and
nonce durations, expiry validation and authority-clock rollback checks are
unchanged.

Verification for this slice used Rust 1.94.1, offline dependencies, the isolated
security target directory and `umask 022`:

- The full kernel run passed 1,426 tests, with two existing ignored DST tests
  (the 10,000-episode nightly sweep and explicit-seed replay).
- The runtime, runtime-core and swarm-authority closure passed 262 tests.
- SQLite caller execution, kernel nonce lifecycle and remote delivery passed
  33 integration tests, including the process and transport boundaries.
- The final control-plane and MCP remote library run passed 987 and 54 tests,
  respectively. The corrected recovery subset also passed all 21 tests.
- The committed receipt-ordering trace shape and native replay passed two
  tests. Apalache 0.50.1 passed `ReceiptBeforeAllow`'s `SafetyInv` at the configured
  length 6, and all 16 registered negative controls reproduced their intended
  invariant violations with validated ITF traces.
- All-target Clippy passed with warnings denied for kernel, SQLite,
  control-plane, runtime-core, runtime and MCP remote. Workspace formatting,
  included regression-file formatting, review slices, public Rust surface,
  formal-slice structure and the security CI contract passed.

These are 2,764 passing Rust tests across the final non-overlapping runs, not
including repeated focused regressions. The two ignored DST tests remain
unexecuted in this run. Local Apalache artifacts are retained under
`/tmp/chio-security-target.rHKDaO/formal-delivery-review/run.DOZJj0` and
`/tmp/chio-security-target.rHKDaO/formal-delivery-negative.Pnl2o3`; they are local
review evidence, not promoted release artifacts.

The formal review remains open. The current mirror manifest still points some
evaluation anchors at forwarding wrappers; the extracted scoped implementations
and readiness helper need explicit review coverage before hashes are refreshed.
The fresh checker still reports ten drift entries across six Rust files. The
receipt-ordering abstraction covers completed tool-output allow publication,
not the incomplete nonce carrier or cross-row recovery. In particular, the
existing reserving-preflight append-failure policy retains the reservation and
returns its reconciliation nonce without claiming tool execution; its explicit
regression remains passing. No model equivalence, full formal qualification or
mirror closeout is claimed here, and no proof-manifest hashes were blessed.

### Formal dispatch anchor reconciliation

The mirror inventory tracked forwarding evaluation methods without requiring
their scoped implementations. The nested forwarding anchor was test-only, not
the production security-context entry. Changes to the actual dispatch bodies
could therefore leave the recorded wrapper hashes unchanged.

The mirror gate now requires both production dispatch bodies, the production
nested entry, shared readiness helpers, credential-profile selection and
reservation, and non-consuming nonce validation for `RevocationPropagation` and
`PostAdmissionDropGuard`. Revocation coverage also requires kernel-mediated
revocation, the shared transition lock, and the receipt-time revocation check
under that lock. The typed coverage contract applies before both checking and
blessing. Regression tests independently remove each of the 32 required
model/symbol pairs, reject mismatched anchors, and show that an implementation
edit drifts while its unchanged forwarding wrapper does not. The old manifest
was rejected for missing the scoped dispatch implementation before expansion.

The mapping now records preparation and payment revalidation, operation-owned
nonce isolation, and the shared revoke/append serialization boundary. The
receipt-ordering model's commentary now distinguishes completed tool-output
allow publication from the incomplete nonce carrier: its existing reserved
preflight append-failure behavior retains a reconciliation nonce, not proof of
tool execution. No model transition or bound was weakened. The two previously
unmapped public Kani harnesses and their covered symbols are registered. They
verify scalar invocation-count and namespace/request equality helpers, not
production-store behavior or cryptographic collision resistance. The generated
proof coverage index and its exact mapping-cardinality test were refreshed.

Local verification uses the unchanged security worktree base
`8b9f9243905dfa61acac82d83438684940777fe3` plus its uncommitted source, Rust
1.94.1, offline dependency resolution and `umask 022`. The full kernel run passed
1,426 tests with the same two ignored DST tests; the formal native replay passed
two tests. All 167 xtask unit tests and all-target xtask Clippy passed. Kani
0.67.0 separately verified both newly mapped harnesses. Apalache 0.50.1 passed
`ReceiptBeforeAllow` at length 6, and all 16 registered negative controls
reproduced the intended violations with validated ITF counterexamples. Local
artifacts are retained under
`/tmp/chio-security-target.rHKDaO/formal-mirror-review/run.sGi6YR` and
`/tmp/chio-security-target.rHKDaO/formal-mirror-negative.03wwOt`.

The portable-core script passed host and `wasm32-unknown-unknown` builds with
default features disabled. Public Kani enrollment and its mutation/runner
contracts passed for all 32 registered proofs. Generated proof coverage,
mapping, formal-slice structure, receipt trace bindings, positive-evidence
runner, workflow aggregation, review slices, public Rust surface, file hygiene,
security CI contract, formatting and whitespace checks passed. These checks
do not qualify the native x86_64 confinement profile or execute the pilot.

The full registered public-core Kani lane subsequently passed all 32 harnesses.
The unchanged positive `PostAdmissionDropGuard` check passed at length 8 after
3,024 seconds under `formal-mirror-review/run.7OrXXc` in the same target
directory. The positive `RevocationPropagation` length-6 check subsequently
passed after 7,043 seconds under `formal-mirror-review/run.qNFjpo`, within its
original 10,800-second timeout. It was not restarted or checked at a smaller
bound. The initial expansion reported 17 expected drift entries; the caller-share
implementation below expanded that reviewed inventory to 22. The later closeout
below reconciles those hashes. Full-workspace and exact-candidate release
qualification remain open. Hash agreement records a reviewed boundary, not a
Rust-to-model equivalence proof.

A fresh read of PR #1117 still reports an open draft with merge state `BLOCKED`
at the base SHA above: 103 successful, nine failed, one cancelled and 15 skipped
checks. There are no running checks in that rollup. These results cover the
published head, not this uncommitted implementation. The failed lanes still
include build/lint/test, MSRV, sidecar images, supply-chain audits and enterprise
security coordination. No CI rerun, external workflow repin, push, merge or
publication was performed by this reconciliation.

### Durable caller sibling-share ownership

Two real-kernel SQLite regressions reproduced distinct ownership defects: a
settled caller reservation left its delegated share stuck in the process-local
registry, while restarting with a live caller reservation forgot that share and
admitted an oversized sibling. Both failed against the previous implementation
and passed after the ownership correction.

The executable hold and its retained admission request now own the caller's
share. A typed store port returns a complete fenced view, validating operation
integrity, retained-request binding and the authority clock in one read
transaction. The SQLite implementation rejects a truncated view and retains
outcome-unknown dispatch owners. Kernel admission combines the durable view with
local evaluation leases while holding the registry lock; reading before taking
that lock would permit a delayed local evaluation to use a stale view. A caller
operation already in the durable view does not acquire a second ephemeral lease.
No additional reservation table, legacy nonce ownership stamp or process-local
caller-ownership map was introduced.

Local verification passed all 15 caller-execution integration tests, including
eight delegated-share regressions: settlement release, restart and settlement,
multiple operations on one child, complete/scoped/bounded/fenced snapshots,
expiry before compensation, ordinary kernel dispatch alongside a caller owner,
concurrent sibling safety and post-denial recovery, and rejection of an external
terminal edit that would otherwise hide a live share from the active-row query.
The test fixture's first tampering attempt was rejected by the existing version
trigger; the final test advances the version too, reaches the unauthorized write,
and verifies that the serving-owner integrity check still rejects the read.
All tests are enrolled through the existing `chio-store-sqlite` integration test
target in the workspace and cognition-market CI commands. Local results do not
establish a hosted exact-head pass.

The adjacent in-kernel nonce lifecycle target also passed all 15 tests, including
startup recovery, interrupted dispatch, strict preflight and nonce-profile
isolation. The full kernel run passed 1,426 tests with two ignored DST tests. The
full SQLite library run passed 1,219 tests with three ignored tests: a child-process helper,
the existing receipt-retention test tracked by issue #1045, and the million-row
release-mode scale proof. Those exclusions are not passes. Strict all-target
Clippy passed for the kernel and SQLite crates. The xtask suite passed 167 unit
tests and 15 integration tests; xtask Clippy, generated coverage, mapping,
formal-slice structure, review slices, public surface, file hygiene, security CI
contract, formatting and whitespace checks passed.

The drop-guard drift inventory now requires seven additional model/symbol pairs
for the caller-share path, bringing the dispatch contract to 39 pairs. Four new
mirror records and the expanded validation record cover the projection and
admission helpers. These are review anchors, not a new SQLite or concurrency
theorem. The mapping explicitly preserves the limits of the abstract child
ledger; the protocol and kernel embedding guide document the ownership rule and
the caller-report evidence boundary. The gate now reports 22 expected drift
entries across 67 registered mirror records. No mirror hashes were blessed in
this slice.

Qualification still needs deterministic interleaving and cancellation coverage
around pending caller ownership, explicit outcome-unknown recovery coverage for
delegated callers, and nested-dispatch overlap coverage. Two concurrently funded
siblings can conservatively both deny; the passing contention test asserts no
oversubscription and subsequent progress after cleanup, not exactly one winner.
The complete view currently scans retained active and outcome-unknown operations;
native load/latency and scale qualification remain open. Provider-signed delivery
receipts, the original full-workspace and exact-candidate gates, dependency
audits, enforced native profile and pilot obligations remain required. No
external workflow repin, CI rerun, push, merge or publication was performed.

### Established caller ownership during pending sibling admission

A deterministic funded-hold interleaving exposed another caller-share defect.
After one caller had reserved its nonce, a second caller could fund a sibling
hold and pause before share admission. Reconciling the first caller then failed
the sibling-sum check against the unadmitted claim. The new regression failed
with that precise denial before the correction and passed afterward.

The opaque share projection now distinguishes an established nonce reservation
from a funded claim that has not crossed that boundary. SQLite already validates
the permanent nonce-reservation row, its Ready snapshot and its exact participant
commit when loading each operation. Reconciliation verifies the current owner
against its snapshot and counts all established owners and local leases, but
unadmitted pending claims cannot displace it. New admissions still count the
complete view, including pending claims. No timestamp or request-id ordering
was introduced, and missing or mismatched ownership still denies.

The deterministic regression also checks that a new admission stays denied while
the pending claim is paused, even after the established owner settles. Releasing
the paused caller then admits it without exceeding the parent. A second test
interrupts a caller immediately after funding, reopens the authority, and proves
that startup compensation releases only that pending owner's quota while the
earlier established reservation remains live and can settle. This is an unwind
and restart test, not a process-kill or distributed-scheduler proof.

The checkpoint, observer and kernel field are all gated by
`admission-test-support`. Normal production builds contain neither its call site
nor observer storage. The checkpoint sits outside the registry lock so the
harness can force the funding/admission interleaving without serializing it away.
Its channels have explicit timeouts, and workers are released before test errors
are propagated. The two interleaving fixtures use a longer nonce lifetime so
they test ownership ordering rather than accidentally test expiry under load;
the separate expiry and compensation regressions remain enabled.

The final caller suite passed 17 tests and the adjacent nonce lifecycle target
passed all 15 tests. The full kernel suite, strict all-target kernel/SQLite
Clippy, and the production no-default-feature kernel check passed. The xtask
suite passed 167 unit tests and 15 integration tests, its all-target Clippy
passed, and generated coverage matches. Public-surface, formal-slice, mapping,
security CI, review-slice, file-hygiene, format and whitespace checks passed.
The code graph was refreshed after the final Rust changes. The full SQLite
library suite subsequently passed 1,219 tests with the same three ignored tests;
no ignored test is counted as passing evidence.
The formal dispatch coverage contract now requires 40 model/symbol pairs,
including the established-reservation predicate. The mapping, protocol and kernel
embedding guide state the distinction without extending the model theorem scope.
At this checkpoint the mirror check reported 22 expected drift entries across
67 records. No model transitions or bounds changed, and hashes remained
unblessed pending the final positive model check. The subsequent closeout is
recorded below.

This closes the reproduced displacement bug, not the entire caller-concurrency
qualification. Progress among competing new pending claims, nested-dispatch
overlap, scan scaling and the original release gates remain open. The follow-up
below adds delegated caller outcome-unknown recovery evidence and records the
completed length-6 `RevocationPropagation` run. No push, remote CI rerun, workflow
repin, merge or publication occurred.

### Caller outcome-unknown retention and formal review closeout

A new real-kernel SQLite regression interrupts caller-report reconciliation
immediately after durable invocation capture and dispatch commitment, with the
post-dispatch cleanup guard armed. It verifies an outcome-unknown terminal, one
captured invocation and no kernel tool-server invocation. After reopening the
authority beyond the nonce expiry, the same operation still owns its delegated
share and captured quota. A competing sibling is denied, and retrying the
original report cannot manufacture an allow or refund the capture.

The existing test-support checkpoint mechanism now names both funded-hold
admission and dispatch commitment. Both boundaries, the observer and its storage
remain absent without `admission-test-support`. The new regression uses the
public reconciliation path and actual SQLite persistence, not a fabricated
terminal row. Its negative control temporarily excluded outcome-unknown
terminals from the complete share query. The test failed at the intended
missing-owner assertion, and the production query was restored before the final
suite. This verifies unwind and restart behavior, not a process-kill boundary or
evidence of external provider execution.

The final caller suite passed all 18 tests and the adjacent nonce lifecycle
target passed all 15. The full kernel suite passed 1,426 tests with the same two
ignored DST tests. The preceding full SQLite library run passed 1,219 tests with
three ignored tests. Strict all-target kernel/SQLite Clippy and the production
no-default-feature kernel check passed. The xtask suite passed 167 unit tests
and 15 integration tests, and its all-target Clippy passed. No ignored test is
counted as executed evidence.

All three outstanding positive model checks now pass at their original bounds:
`ReceiptBeforeAllow` at length 6, `PostAdmissionDropGuard` at length 8 and
`RevocationPropagation` at length 6. Together with the completed 32 public-core
Kani harnesses and 16 calibrated negative controls, this allowed the reviewed
source-hash reconciliation. Blessing updated exactly 22 of 67 mirror records
(22 aggregate hashes and 39 symbol hashes). A before/after comparison confirmed
that only hashes changed, and the subsequent mirror check passed all 67 records.
The required coverage contract still contains all 40 model/symbol pairs. Neither
model transitions nor bounds were changed to achieve this result. These are
bounded abstract-model checks and reviewed implementation anchors, not a
Rust-to-model equivalence or concrete cross-row crash-recovery proof.

The generated coverage index was regenerated after the hash update and matches
all 58 rows and 168 artifacts. Mapping, formal-slice structure, public Rust
surface, file hygiene, security CI contract, review slices, formatting and
whitespace checks passed. The sidecar comments and Python SDK guidance now
distinguish legacy nonce rejection from durable completed-receipt redelivery:
retrying reconciliation cannot authorize another external execution. All 38
Python client tests passed in the SDK's existing virtual environment. No
runtime sidecar behavior or Python request format changed.

An important caller-execution boundary remains open. The sidecar and Python SDK
describe a trusted external executor that sends its report after executing; the
kernel performs its dispatch commitment while reconciling that report. The
inspected reservation path keeps a caller operation Ready while its nonce is
live and permits expiry compensation afterward. No external dispatch-start
commitment was found in that inspected path. The next delivery-contract work
must resolve the external-effect-before-report interval, including report loss,
restart and nonce expiry, with authenticated dispatch/delivery evidence and
end-to-end negative controls. The new test does not close that interval, and
caller-supplied reports are not provider-signed delivery receipts. This is a
remaining design and qualification gap, not a reproduced external exploit.

All original roadmap and release gates remain in force, including complete
caller-concurrency qualification, provider-signed delivery receipts,
full-workspace and exact-candidate hosted checks, dependency audits, native
x86_64 enforcement and the operational pilot. No push, remote CI rerun, external
workflow repin, merge or publication was performed during this closeout.

### External effect before caller report: reproduced contract gap

The follow-up real-kernel SQLite harness reproduced the previously unverified
external-effect-before-report interval. It loads the actual retained nonce
through the fenced authority, creates and syncs a local file outside the
kernel's registered tool server, closes the authority without reconciliation,
advances beyond the nonce expiry, and reopens it. The file remains, but the
grant's `(reserved, captured)` counts become `(0, 0)`. The required captured
count is one: a lost report must not refund an executed external effect.
The strengthened regression also receives `Allow` for a second operation under
the same one-invocation capability. Its combined assertion observes
`((0, 0), Allow)` where the required result is `((0, 1), Deny)`.

The isolated command executed one test and failed at that exact quota assertion:

```sh
cargo +1.94.1 test -p chio-store-sqlite \
  --test execution_nonce_caller_execution \
  an_external_effect_with_a_lost_report --offline -- --ignored --nocapture
```

The test is explicitly ignored in the normal suite with the reason
`requires durable caller dispatch-start handshake before external effect`.
It is an executable unimplemented contract, not passing qualification, and must
be enabled after the handshake is implemented. No production recovery behavior
was changed to make the test green. This harness establishes a trusted-caller
workflow counterexample; it is not a qualified provider transport, process-kill
test or demonstrated remote exploit.

The ordinary caller suite passes 18 tests with this one explicitly ignored
unimplemented contract. Targeted Clippy, the 67-entry formal mirror check,
generated coverage, security CI contract, review slices, formatting and
whitespace checks pass. Coverage regeneration changed only the Rust-file
inventory input digest and combined input digest; its 58 rows and 168 artifacts
are unchanged. These passing checks do not convert the contract counterexample
into passing delivery evidence.

The [caller dispatch commitment design](../superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md)
defines the required state transitions, private retained admission context,
authenticated dispatch authorization, executor-owned durable claim, report
binding, expiry behavior and crash/concurrency matrix. The implementation must
reuse the original operation, physical capture and terminal pipeline. A fresh
evaluation of a late report cannot substitute for the dispatch-time context.
Changing all reservations to non-expiring holds or declaring in-kernel dispatch
a substitute would not complete this caller-delivery requirement.

This is a remaining implementation defect for the intended external caller
profile. The earlier post-commit retention regression still covers its distinct
kernel-report-pipeline boundary; neither it nor the passing model checks close
this newly reproduced interval. All original roadmap and launch gates remain
required, and no release or publication was authorized by these results.

### Caller dispatch context: atomic storage groundwork

The implementation adds a private canonical context frame and a dedicated
fenced authority operation that commits its digest and physical row with actual
invocation capture and nonce/operation `DispatchCommitted`. Capture preparation
remains a separate earlier intent; exact replay and restart retain the original bytes.
Generic compare-and-swap cannot attach this participant independently. Backends
without the new atomic port fail closed.

Operation reads, replay lookups, recovery scans and startup verify the physical
context against its committed attachment and retained original request. Storage
reads bound the BLOB before allocating it. Regression coverage includes failed
insertion rollback, missing or modified rows, orphan ownership, oversized bytes,
canonical/binding substitution, expiry, owner fencing and clock regression.

Schema 18 refuses ambiguous legacy caller history, including refunded caller
terminals and unversioned databases. The migration does not infer that a legacy
compensation means no external effect occurred. Ordinary nonce history migrates
without invented context or capture, and rejected migrations do not advance the
schema stamp.

This is the storage framing portion of the dispatch design's first step, not a
complete kernel admission snapshot. The owning kernel still needs a typed
producer and decoder for the original guard, receipt, federation, payment,
credential and security/runtime context. The frame's canonical JSON payload is
not verified authority. No current kernel start route or external executor uses
the new port. The reproduced lost-report/expiry counterexample remains open;
the signed authorization, executor ledger, report path, sidecar/SDK integration
and full crash/concurrency qualification are still required. These changes do
not close any hosted, native-platform or operational launch gate.

Historical verification of the initial capture-preparation implementation on
`security/launch-integration`, based on
`8b9f9243905dfa61acac82d83438684940777fe3` plus the uncommitted integration
changes, used Rust 1.94.1 with offline Cargo, incremental compilation disabled,
and umask 022. The following counts predate the revised actual-capture boundary
and frozen return-context work; they do not qualify the current changes:

- The full kernel suite passed 1,426 tests with two ignored.
- The final full SQLite library suite passed 1,233 tests with three ignored.
  Its 14 new caller-context tests also passed separately. Failure injection
  covers both context insertion and the later nonce-history insertion, proving
  rollback leaves neither a changed operation nor a stranded context row.
- Caller-execution integration passed 18 tests with the missing-handshake
  contract explicitly ignored; nonce kernel-lifecycle integration passed 15.
- Running that ignored external-effect contract explicitly still failed at
  `((0, 0), Allow)` versus `((0, 1), Deny)`. This is the same open workflow
  defect, not a passing test or provider-delivery qualification.
- Kernel/SQLite all-target Clippy with warnings denied, the no-default-features
  kernel check, formatting, public-surface policy, Rust file hygiene, review
  slices, security CI contract and whitespace checks passed.
- All 67 formal mirror entries matched. Generated coverage was regenerated and
  verified at 58 rows and 168 artifacts. Neither check proves the new caller
  handshake or supplies missing Rust-to-model refinement evidence.

The Cargo lockfile was unchanged during this slice. No commit, push, hosted CI
rerun, workflow repin, merge or publication was performed.

### Caller context: actual capture boundary and frozen return component

Review of the dispatch sequence showed that payment authorization, the finding
pool claim and the final security hook follow `CapturePending`. The private
context must therefore join actual quota capture and `DispatchCommitted`, not
the earlier capture-preparation transition. The dedicated qualified store port
now commits the context row, immutable operation digest, quota capture and nonce
commitment in one existing anchored transaction. Replay cannot omit the context;
failure injection at either context insertion or later nonce-history insertion
rolls the entire capture back. Financial effects remain after their durable
intent; no operation versions or state transitions were added.

Ordinary and nested kernel dispatch now share a frozen in-memory return-context
component. It carries the selected grant, stream limits, admission receipt and
purchase/recovery metadata, pre-invocation guard evidence and security invocation
identity. Request material is bound before capture and checked again before
return persistence. Transient credentials are excluded from the new digest.
The existing raw outcome's recovery-request serialization is unchanged; this
does not establish a new credential-retention or custody guarantee.

Ordinary calls still do not require the bounded original-request artifact.
Their live request is checked against the immutable admission binding before
the effect, then only an in-memory digest is retained. Caller/nonce profiles
must retain their original provenance; it is never reconstructed when missing.
Seven new tests cover pre-commit rejection, selected-grant/request substitution,
cross-operation confusion with the same request ID, configuration changes after
freezing, rejection of post-commit freezing, and ordinary/nested requests larger
than the caller artifact limit. Actual output, cost, elapsed time and memory-read
provenance remain return observations, not invented admission facts.

This is not yet the complete durable caller snapshot. Federation verification,
credential and security/runtime custody, private decoding, authenticated start,
executor claim, historical report finalization and sidecar/SDK integration
remain required. The explicit external-effect test was rerun and still fails
at the intended `((0, 0), Allow)` versus `((0, 1), Deny)` assertion. It remains
an open workflow defect, not an external transport qualification.

Local verification of this revised slice used Rust 1.94.1, offline Cargo,
incremental compilation disabled and umask 022 in the isolated integration
worktree at `8b9f9243905dfa61acac82d83438684940777fe3` plus uncommitted changes:

- The full `chio-kernel` suite passed, including 1,222 library tests and the
  integration/doc tests. Two existing DST scenarios remain ignored. All seven
  new return-context regressions executed and passed.
- SQLite library tests passed 1,233 with three ignored, including the revised
  14-test caller-context group. Caller integration passed 18 with the open
  external-effect contract ignored; nonce lifecycle integration passed all 15.
- Kernel/SQLite all-target Clippy with warnings denied, the kernel
  no-default-features check, formatting, public-surface policy, Rust file
  hygiene, review slices, security CI contract and whitespace checks passed.
  Extracting the return component brought the terminal coordinator below its
  normal size limit; its obsolete file-size exception was removed.
- The four changed dispatch mirror entries were reviewed against the unchanged
  revocation and drop-guard abstractions. All 67 entries match, the formal
  mapping check passes, and generated coverage matches 58 rows/168 artifacts.
  No model transitions, resource bounds or theorem claims were weakened or
  extended. The repository code graph was refreshed.

The lockfile did not change during this slice. These local results do not
qualify the full workspace, hosted candidate, native profile or operational
pilot. No commit, push, CI rerun, workflow repin, merge or publication occurred.

### Returned federation evidence and failure-boundary isolation

The frozen return component now includes bounded private federation evidence:
the original signed DSSE envelope, locally accepted report binding, original
peer pins and admission time. Before a tool effect, the kernel checks those
materials against the admitted participant identities and request. After return,
the new private raw-outcome schema retains them in the content-addressed blob.
Recovery validates the qualified outcome's dispatch and blob bindings before
decoding the snapshot and re-verifying the original signatures. It does not
promote deserialized metadata into `VerifiedFederationTreatyMaterial`.

Newly recorded outcomes can complete missing bilateral projections without
fresh runtime admission. Startup gives each finalization an independent
evaluation scope, preventing concurrent operations with the same request ID
from exchanging treaty/report bindings. Public replay still requires a valid
capability, current revocation checks, a live peer and a registered target.
Historical internal recovery uses the original pin time; changed local signing
identity fails closed. Legacy raw schemas keep their existing recovery behavior.

Independent review exposed two integration bugs in this slice. A known local
freeze rejection was routed through ambiguous-commit retention, leaving
pre-dispatch resources outstanding. The shared handler now distinguishes that
case and uses existing compensation, while unconfirmed store commits retain
custody. Concurrent startup finalization also lacked evaluation isolation; it
now scopes each attempt through the existing task-local RAII mechanism.

Payment regressions then exposed a pre-existing unwind-reference mismatch:
authorization and restart recovery used the durable operation ID, but initial
release/refund used the caller request ID. Both initial cleanup and drop-guard
unwind now use the original operation reference. Credential disposition comes
from the credential owner, not inferred payment presence. Raw and persisted
outcome Debug implementations also omit private payloads and credentials.

The payment-reference audit also covered lost acknowledgements: authorization
and unwind failure receipts now name the same adapter operation as the actual
attempt. A shared reference selector preserves the request-ID namespace for
legacy payments and uses the operation ID for a durable payment participant.
Ordinary and nested financial dispatch now require that participant, not merely
the presence of any durable admission. A governed prepayment quote paired with
a non-monetary grant is denied before authorization in the enforced profile;
the explicitly unsafe ephemeral financial profile remains separate.

This remains one component of the complete caller snapshot. Runtime and
credential ownership need operation-bound authority records; existing durable
security evidence needs a recoverable connection to the caller operation.
Authenticated start, signed executor authorization, executor-owned claim,
historical delivery reporting, sidecar/SDK integration and external crash/race
qualification remain required. The lost-report contract remains open. No
publication or full-roadmap completion is claimed.

The next runtime-custody boundary requires one qualified replay authority.
Runtime-core's current SQLite replay markers are independent of the admission
store and its owner fence. Copying an epoch into those markers, or adding a
second replay ledger, would not establish custody. The next implementation must
separate evidence preparation from consumption, claim the exact participant set
through the existing qualified admission transaction, and use owner-qualified
references for cleanup and recovery. Legacy consumers must not remain able to
consume or delete the same resources through another replay namespace. These
requirements are detailed in the caller-dispatch design; they are not yet
implemented or qualified.

Verification of this slice:

- The final kernel suite passed all 1,241 library tests and its integration and
  documentation tests. Two existing DST cases remain ignored. The 12 retained
  federation regressions and seven payment-boundary regressions executed; each
  payment regression covers ordinary and nested dispatch.
- The real SQLite federation restart case retains the original raw evidence,
  completes the missing bilateral projection without fresh runtime admission,
  and verifies exact receipt replay without a second tool effect. The concurrent
  recovery test deliberately shares the production federation map between two
  independently fenced kernel fixtures. It is not a claim of complete
  multi-process caller-execution qualification.
- After the final payment changes, SQLite caller integration passed 18 with the
  lost-report contract ignored, nonce lifecycle passed 15, and runtime admission
  passed 57. The earlier SQLite library pass in this slice was 1,233 with three
  ignored; it preceded the final payment guard and receipt-reference changes.
- Kernel/SQLite all-target Clippy with warnings denied and the kernel
  no-default-features check pass on the final code. Formatting, explicit
  formatting checks for included tests, public-surface policy, Rust file hygiene,
  review slices, the security CI contract and whitespace checks also pass. No
  file-size exceptions were expanded for these changes.
- The formal mirror gate matches all 69 entries. Its 21 focused tests and the
  mapping check pass; generated coverage matches 58 rows and 168 artifacts. The
  new payment guard and signed failure references do not extend model theorem
  scope. No transitions, resource bounds or assumptions were weakened.

The lockfile did not change during this slice. The code graph was refreshed.
These local results do not qualify the full workspace, published candidate,
native launch profile or operational pilot. No commit, push, CI rerun, workflow
repin, merge or publication occurred. The complete roadmap remains open.

### Non-consuming runtime preparation and trust-floor serialization

Runtime admission now separates read-only preparation from replay consumption.
The existing hook loads one bundle, checks its lookup identity and optional hash
pin, and gives that same snapshot to treaty and core verification. The private
owned plan contains validated request, policy and trust inputs; it cannot be
cloned or deserialized into authority. The hook plan remains bound to its
originating configured hook. Standalone admission uses the same core path.

Invalid preparation performs no continuation or destructive lease consumption,
trust-floor write or compensating release. Dropping a valid prepared plan also
requires no cleanup. Only the subsequent consuming step emits reservation
metadata or accepted treaty material. A missing bundle now denies at the initial
lookup, before core profile checks; this intentionally changes denial precedence
and omits the old null policy-decision field, without allowing missing evidence.

Commit preserves the existing ambiguity boundary: a lost acknowledgement after
consumption does not prove ownership or permit releasing that participant.
Earlier confirmed participants unwind once. A failed release is not retried
against a resource that another attempt may have reacquired. A trust-floor write
followed by panic leaves the floor advanced and releases confirmed reservations.

Review also found an existing race in the default trust-floor read/write
fallback, inherited by memory and JSON admission stores. Both now validate and
update under one lock. Core trait defaults reject with
`runtime_trust_floor_store_unsupported` unless a backend explicitly supplies the
atomic operation. Existing facade methods remain required and its adapters
delegate that operation. JSON locking covers shared handles only, not independent
opens or other processes; SQLite retains its transactional implementation.

This is the preparation prerequisite, not operation-owned runtime custody.
The qualified admission transaction still needs exact participant claims,
immutable operation attachment, owner-qualified compensation and recovery, and
enforced sealing/import of legacy replay state before activation. The complete
caller snapshot, authenticated external start, executor authorization and claim,
lost-report recovery, sidecar/SDK integration and launch qualification remain
open. No second replay ledger or metadata-only custody shortcut was introduced.

Local verification of this slice used Rust 1.94.1, offline Cargo, incremental
compilation disabled and umask 022 at
`8b9f9243905dfa61acac82d83438684940777fe3` plus uncommitted integration changes:

- The complete runtime-core suite passes all 201 tests; the runtime facade
  passes all 13 tests. No tests in those suites are ignored. Preparation/drop,
  exact bundle identity and snapshot use, confirmed-only cleanup and
  mutate-then-error/panic paths execute against the production admission path.
- Four store-race tests each run eight rounds with four synchronized contenders.
  They require one exact winner, conflicting-version rejection, idempotent
  replay, unchanged state after rollback/wrong-parent rejection, and persisted
  winners for file-backed stores. SQLite uses independent connections; JSON
  uses shared instances. This is not crash-atomic or multi-process JSON evidence.
- Runtime-core/runtime all-target Clippy with warnings denied, workspace
  formatting, explicit included-test formatting, public-surface policy, Rust
  file hygiene, security CI contract and whitespace checks pass. WIP path
  classification covers 204 files across 11 slices; the normal commit-only
  review-slice command sees no committed diff against this same base SHA.
- All 73 formal mirror entries match; the 21 focused mirror tests and formal
  mapping gate pass. Generated coverage matches 58 rows and 168 artifacts.
  Moved lifecycle implementations are mandatory drift anchors. Trust-floor
  concurrency remains runtime evidence outside the unchanged aggregate lease
  model, not a new theorem or weakened assumption.

The lockfile did not change during this slice. The repository code graph was
refreshed. These results do not qualify the full workspace, hosted candidate,
native launch profile or operational pilot.
No commit, push, CI rerun, workflow repin, merge or publication occurred. The
complete roadmap remains open.

### Storage-enforced legacy runtime replay source seal

The SQLite runtime store and its public facade now expose explicit source seal,
load and verification operations. One IMMEDIATE transaction inventories every
destructive lease, treaty continuation and swarm continuation and installs
persistent INSERT/UPDATE/DELETE rejection triggers on those three tables and
the singleton seal record. New typed mutation calls reject sealed sources even
when a release would otherwise be a no-op. Existing SQL connections and prepared
statements cannot bypass the committed triggers through ordinary legacy DML.
Unsealed legacy behavior remains available; opening a database does not seal it.

The canonical, domain-separated inventory digest binds operator-selected source,
runtime-authority and destination-authority labels, the exact barrier catalog,
the actual SQLite file descriptor's device/inode/single-link identity and all
historical markers. The implementation reuses the existing file-identity OS
boundary and keeps runtime-core unsafe-free. It checks untrusted storage types
and sizes before allocating rows or blobs. Complete inventory limits are 16,384
markers and 8 MiB of canonical evidence, with identifiers limited to 512 bytes.
Over-limit input rejects and rolls back rather than producing a partial seal.

Sealing requires synchronous FULL and WAL; readback observes SQLite's committed
state without depending on a checkpoint. Exact retries return the existing seal.
A lost commit acknowledgement requires authoritative load/verification, never
an optimistic return to legacy writes. Partial or corrupt seals reject before
schema initialization can repair missing protected objects. Verification also
rejects copied files, hard links, symlink paths and open-descriptor/path mismatch.

This implements source retirement only. There is no destination import,
qualified runtime activation or operation-owned claim in this slice. Historical
admission IDs are not authenticated custody. Migration must quiesce effects
already admitted by legacy consumers and retain independent source expectations.
Persistent triggers do not defend against privileged schema changes, disabled
triggers, complete erasure of seal evidence or filesystem rollback. The source
seal has no independent antirollback anchor and cannot retract an in-memory
effect admitted before sealing. None of these limits authorize a second active
replay namespace, invented historical ownership or ambiguous refunds.

Local verification at `8b9f9243905dfa61acac82d83438684940777fe3` plus the
uncommitted integration changes used Rust 1.94.1, offline Cargo, incremental
compilation disabled and umask 022:

- Runtime-core passes all 234 tests and the facade passes all 14 tests, with no
  ignored tests. This includes four source-artifact tests, 29 SQLite source-seal
  tests and the facade seal/error-propagation test.
- Successful file-backed sealing tests are Unix-specific. Non-Unix rejection
  tests cover the identity helper, source store and facade without retiring
  legacy replay. They were added but not executed on this Linux host. The helper's
  Unix-only imports are now conditional; its audited unsafe logic is unchanged.
- The storage suite exercises prepared legacy SQL, all three replay kinds,
  stale WAL snapshots, a competing writer, complete/empty inventories, missing
  or modified barriers and records, bounded corrupt storage, file-identity
  attacks and exact reopen/retry. The subprocess case exits after the committed
  seal without Rust destructors or a response to its parent; a fresh process
  observes the same complete inventory and rejects legacy mutations. It does
  not qualify arbitrary mid-commit power loss or a destination activation path.
- Runtime-core/runtime all-target Clippy with warnings denied passes. All 73
  formal mirror entries match, and the 21 focused mirror tests pass. Regenerated
  proof coverage matches 58 rows and 168 artifacts. These storage checks do not
  extend the aggregate drop-guard model's theorem scope or alter its assumptions.
- The native file-identity unit test and its all-target Clippy pass. Workspace
  formatting, explicit included-test formatting, public-surface policy, Rust
  file hygiene, formal mapping and whitespace checks pass. The security CI
  checker and its trust-boundary mutation regression suite pass. Explicit WIP
  classification covers 224 files across 11 slices; the commit-only review-slice
  check sees no committed diff against this same base SHA.

The repository code graph was refreshed after the final code changes.

The lockfile changes only add the existing workspace file-identity dependency
to runtime-core and the existing tempfile test dependency to the facade. No
package version changes were introduced. The matching local security checker
and evidence-image lockfile digests were updated together; workflow pins and
dependency-audit requirements are unchanged. No user database was sealed.

At the source-seal checkpoint, the next implementation was the qualified
destination: unresolved legacy marker import, atomic operation-bound participant
claims, explicit preflight and
dispatch lifecycle, owner-qualified cleanup and restart recovery, followed by
interruption-safe activation. Full caller snapshot, credential/security custody,
authenticated start, executor-owned claims, lost-report recovery, sidecar/SDK
integration and the original launch gates remain open. This is not a full
workspace, native profile, hosted candidate or operational-pilot qualification.
No commit, push, CI rerun, workflow repin, merge or publication occurred.

### Anchored runtime replay expectation and imported-inactive destination

The qualified SQLite admission store now retains a source expectation before
retiring the legacy replay source, then imports its complete inventory as
inactive history. This advances the source-seal prerequisite above; it does not
implement runtime participant ownership or activate the qualified profile.

The operator configures the source port and independent runtime/source labels.
The destination first checks its current owner fence and migration clock, then
previews the actual source without consuming resources or installing barriers.
It binds the candidate to its own actual store UUID and durably pins one exact
expectation through the existing write/commit/anchor path. Canonical inventory
and digest validation do not turn `RuntimeReplaySourceSnapshotV1` into authority.
`RuntimeReplaySourcePort` is trusted configured code, not an agent-selected
adapter, and implementing the public trait alone does not qualify a source.

Import loads that anchored expectation before any source mutation. The SQLite
source compares its complete inventory, physical identity and barrier definition
with the expected bytes before installing its seal in the same IMMEDIATE
transaction. A changed source rejects rather than updating the expectation.
After live seal verification, the destination atomically retains all historical
markers and the import event. Empty sources follow the same expectation, seal
and import protocol; an empty inventory does not bypass retirement.

Expectations, migration events and unresolved legacy tombstones are immutable
storage history. The global authority chain authenticates the expectation and
import events, their historical fences, exact inventory and local projection
references; coverage verification requires matching local and global history.
No synthetic admission operation or independent unanchored import ledger is
created. Canonical row verification and the existing anchor reject missing,
modified or partially imported history without reconstructing it. Conditional
INSERT barriers also reject replacement conflicts when SQLite recursive
triggers are disabled, including collisions on the expectation's separate
source and generation keys.
All three tables use `WITHOUT ROWID`, so implicit row identifiers cannot bypass
those declared-key replacement barriers.

The destination bounds the complete pending and imported inventory to 128
expectations, 64 MiB of canonical source evidence and 65,536 markers. Each source
retains the prior 16,384-marker and 8 MiB limits. Capacity is reserved at pinning
before a source is frozen; no over-limit result is truncated or treated as a
successful partial import. Schema v19 adds this migration history and refuses
older schema stamps carrying new migration objects. Historical fixture upgrades
remove only asserted-empty new tables, not actual migration evidence.

Exact pin retries return the original anchored generation without asking an
already sealed source for another preview. A pending import can resume after
losing its source-seal acknowledgement using the same expectation. Once import
is recorded, retry performs live verification only: missing barriers are damage,
not permission to reseal and hide a post-import mutation window. Exact retries
do not append another destination generation or global commit.

A nonblocking RAII guard is shared by every import adapter of the destination
serving owner. Concurrent or reentrant import attempts reject before another
source mutation, including attempts against another runtime namespace. This
guard does not hold the destination database mutex or a transaction across
source callbacks. The destination revalidates ownership and its migration-wide
clock high-water before committing. The clock history is specific to migration
events; this adds no fabricated admission commit or global cross-domain clock
claim.

Imported tombstones are keyed by stable runtime authority, participant kind and
original resource ID. Their historical admission IDs describe past markers, not
authenticated operation owners. Changing an inventory digest, source label or
historical admission ID cannot create another replay namespace. Imported-inactive
history does not authorize dispatch, acquire a runtime participant, establish
cleanup authority, permit an ambiguous refund or enable a destination profile.

Source retirement still requires operator quiescence and reconciliation of
already admitted effects. The source barrier does not defeat privileged schema
changes, disabled enforcement, complete evidence erasure or filesystem rollback.
The qualified destination independently anchors its expectation and import
history, but does not grant the source its own antirollback mechanism or retract
an in-memory legacy admission. Existing independently sealed sources cannot be
discovered as fresh unsealed previews. There is no automatic unseal, source
generation replacement or shortcut around unresolved historical custody.

Local verification at `8b9f9243905dfa61acac82d83438684940777fe3` plus the
uncommitted integration changes used Rust 1.94.1, offline Cargo, incremental
compilation disabled and umask 022:

- Runtime-core passes all 251 tests and the facade passes all 15 tests, with no
  ignored tests. New real-source tests cover non-consuming preview, complete
  identity/inventory drift rejection, exact sealing, empty/populated destination
  import, owner rotation, concurrent/reentrant import exclusion, and lost
  acknowledgement or panic after the source commit. Facade trait-object tests
  preserve exact results and rejection errors without persistent preview writes.
- The complete SQLite library suite passes 1,257 tests, with three existing
  ignored entries: the million-receipt scale proof, the retention property test
  disabled for the documented runner issue, and the child-process serving-owner
  helper. The parent test separately executes that helper successfully. These
  ignored entries are not counted as passing coverage.
- All 17 destination migration regressions pass, including seven injected SQL
  cutpoints spanning expectation writes, partial tombstone insertion, local
  events and global commits. Each failure reaches the injected write error,
  rolls back partial destination history, retains an already sealed source and
  permits exact complete retry. Five schema tests and three predecessor global
  catalog tests cover unqualified namespace rejection, missing barriers,
  hidden-row-ID replacement and unchanged historical chains.
- The new source-to-destination interruption test closes and reopens both stores
  after the source seal but before the destination import. It is normal
  interruption-boundary restart evidence, not a subprocess or power-loss test.
  The existing source-only subprocess exit test also passes; neither qualifies
  a complete multi-process migration crash matrix or runtime activation.
- Successful real-source tests are Unix-specific. Explicit non-Unix rejection
  paths were added but were not executed on this Linux host.
- All 73 formal mirror entries match, the 21 focused mirror tests pass, and
  generated coverage matches 58 rows and 168 artifacts. The formal mapping,
  security CI contract and trust-boundary mutation regression suite pass. These
  results do not add a migration theorem or change aggregate model assumptions.
- All-target Clippy with warnings denied passes for kernel, runtime-core,
  runtime and SQLite. Workspace formatting, explicit included-test formatting,
  public-surface policy, Rust file hygiene and whitespace checks pass. Explicit
  WIP classification covers 249 files across 11 slices; the commit-only
  review-slice check sees no committed diff against this same base SHA.

The code graph was refreshed after the final code changes (160,324 nodes,
416,780 edges and 6,918 communities).
The lockfile did not change during this slice. No user database was sealed and
no commit, push, CI rerun, workflow repin, merge or publication occurred. These
results do not qualify the full workspace, native launch profile, hosted
candidate or operational pilot.

The current frontier is atomic operation-bound runtime participant ownership:
phase-aware immutable claims and attachments, ordinary/nested and
nonce-preflight/dispatch parity, exact physical disposition checks,
owner-qualified compensation and restart recovery. Activation must then prove
one enforcing replay backend and interruption-safe transition from inactive
history. The complete durable caller snapshot, credential/security custody,
authenticated start, independently pinned executor authorization and durable
claim, authenticated historical reports, lost-report recovery and sidecar/SDK
integration remain open. The original protocol, active-defense, enterprise,
dependency, native enforcement, exact-candidate and operational launch gates
remain requirements, not deferred exceptions to this slice.

### Operation-owned runtime replay custody (store primitive)

The next local slice introduces schema v20 and real atomic runtime replay
claims in the qualified SQLite admission authority. This remains an inactive
store primitive, not an activated runtime profile or completed caller-delivery
boundary.

- A configured verifier supplies one complete, ordered intent containing the
  exact request-binding hash, matching grant, phase, preparation-plan digest,
  pinned source generation and at most one destructive, treaty and swarm
  resource. The store checks the retained original request and exact imported
  generation. It does not independently verify runtime artifact signatures or
  derive the preparation-plan digest; those remain verifier responsibilities.
- An IMMEDIATE transaction reserves the entire resource set or none of it.
  Replay identity is runtime authority, participant kind and original resource
  ID. Neither artifact digest, operation ID nor episode ID creates another spend
  namespace. Imported historical tombstones remain permanent conflicts.
- One immutable ledger attachment binds the operation to its runtime authority
  and source generation. Every claim and release has a separate canonical
  physical record and named admission commit, covered by the existing global
  chain and rollback anchor. Reads, replay-key lookup and recovery enumeration
  validate physical history. Exact commit coverage rejects missing episodes or
  releases even when another episode still owns the same ledger attachment.
- There is at most one live episode and at most 128 retained episodes per
  operation. Exact unreleased retry returns the same reference; a released
  episode cannot be reacquired. A historical release acknowledgement never
  releases a successor. Every mutation requires the actual current owner fence
  and exact-version recovery lease. The first claim advances the operation
  version, so its caller must renew that lease before a subsequent mutation.
- Dispatch commitment requires a live dispatch-phase claim whenever this ledger
  is attached. After commitment, its resources remain retained through expiry,
  unknown outcomes and recovery. Generic compare-and-swap cannot fabricate the
  ledger or commit a released claim. Pre-dispatch terminalization cannot discard
  a live claim. Fenced readback recovers original references and dispositions
  after reopening without re-preparing expired runtime artifacts.
- Migration rejects a partial unqualified claim namespace and damaged canonical
  v19 predecessors. The commit-table rebuild preserves historical rows, hashes,
  sequence numbers, fences, observed times and foreign-key targets. A populated
  upgrade regression reopens real admission and imported-source history under
  the existing rollback anchor. New physical tables are bounded, immutable and
  WITHOUT ROWID, including explicit replacement rejection.

Local verification for this slice:

- The expanded SQLite library suite passes 1,273 tests with the same three
  existing ignored entries described above. All 12 new lifecycle, cutpoint,
  corruption, populated-upgrade and fenced-readback regressions pass, along
  with four new schema tests. These are real store transactions and normal
  close/reopen tests, not power-loss or process-crash qualification.
- All 1,241 kernel library tests pass, with no ignored tests. Scoped all-target
  Clippy passes for kernel, SQLite, runtime-core and runtime with warnings denied.
  All 73 formal mirrors still match; no mirror was blessed and no new runtime
  custody theorem is claimed. The 21 focused mirror tests pass. Generated proof
  coverage was refreshed and rechecked at 58 rows and 168 artifacts.
- The complete runtime-core and runtime suites pass, including the real
  source-to-destination migration tests. Security CI contract validation and
  its trust-boundary/evidence mutation regressions pass.
- Workspace and explicit included-test formatting, public-surface policy, Rust
  file hygiene, formal mapping and whitespace checks pass. WIP classification
  covers 260 files across 11 slices. The commit-only check still sees zero files
  against the unchanged base SHA; it does not review this uncommitted work.
- The code graph refresh completed with 160,461 nodes, 417,262 edges and 6,996
  communities. Cargo.lock is unchanged during this slice.

These results do not qualify the full workspace, a native launch profile,
hosted candidate or operational pilot. No commit, push, hosted CI rerun,
workflow repin, merge, profile activation or publication occurred.

Still open: the configured runtime hook must derive and submit its actual
prepared plan through a qualified port, retain authoritative references, and
route ordinary, nested, nonce-preflight and dispatch cleanup through these
primitives. The nonce preflight budget and issuance attachment allowlists have
not been widened; they still reject an unintegrated runtime ledger. Kernel
Drop/restart cleanup and phase parity require end-to-end tests. Activation must
prove one enforcing replay backend, not simultaneous legacy and qualified
consumption. Concurrent-process races, a process-crash/lost-ack matrix and real
budget/runtime integration are not qualified by these store tests. Full caller
context, credential/security custody, authenticated external start, independent
executor claims and reports, SDK/sidecars and every original launch gate remain
required.

### Kernel recovery of operation-owned runtime custody

The next integration slice connects replay custody to the kernel's existing
durable admission authority. It does not activate the runtime profile.

- The admission-operation trait now exposes atomic claim, exact release and
  fenced history readback. Unsupported implementations reject. SQLite forwards
  these calls to its existing qualified physical store, with no alternate replay
  backend and no authority taken from agent metadata.
- The shared pre-dispatch compensator recovers the exact retained operation and
  claim history under the current owner fence, operation lease and mutation
  sequencer. Within that compensator, physical runtime release precedes
  no-effect assertions and monetary unwind. Missing, empty, oversized,
  inconsistent or substituted history rejects instead of permitting cleanup.
- Release success requires a second fenced read showing unchanged references
  and intents, with only the live episode marked released. A no-op success or
  replaced reference cannot terminalize the operation. Unknown release outcome
  remains unresolved until a retry reads the durable disposition; an already
  completed release is not repeated.
- Restart recovery can release both nonce-preflight and dispatch-phase claims
  without a runtime hook or fresh artifact preparation. Released predecessor
  episodes and imported historical tombstones survive. Once dispatch commits,
  unknown-outcome recovery retains the claim and never frees its resources.

Local verification for this slice:

- Seven new regressions pass: four kernel boundary fault tests and three real
  SQLite recovery tests. The SQLite tests close and reopen the serving owner,
  exercise both phases, and inject failures before release and terminal
  projection. The committed-dispatch state fixture does not qualify real budget
  settlement. These are not power-loss or process-crash tests.
- All 1,245 kernel library tests pass with no ignored tests. Runtime-core's
  251 tests and the runtime facade's 15 tests pass with no ignored tests.
  Scoped all-target Clippy passes for kernel, SQLite, runtime-core and runtime
  with warnings denied, including the final formatting-only correction.
- The complete SQLite library suite passes 1,276 tests with zero failures and
  the same three existing ignored entries. Its parent test separately executes
  the serving-owner child-process helper successfully. The full run completed
  in 472.95 seconds under `umask 022`.
- All 73 formal mirrors match without blessing; the 21 focused mirror tests
  pass. Proof coverage was regenerated and rechecked at 58 rows and 168
  artifacts. No new runtime custody theorem is claimed. Formal mapping,
  public-surface policy, Rust file hygiene, workspace and explicit included-test
  formatting, and whitespace checks pass. The security CI contract and its
  trust-boundary/evidence mutation tests pass.
- WIP classification covers 264 files across 11 slices. The commit-only check
  still sees zero files against unchanged HEAD. Cargo.lock is unchanged during
  this slice. The code-graph refresh completed with 160,516 nodes, 417,442 edges
  and 6,958 communities.

Still open: operation-scoped runtime hook acquisition and prepared-plan binding,
ordinary/nested grant fallback, nonce-preflight budget and issuance integration,
live-path and Drop phase parity, and interruption-safe activation of one replay
authority. The shared compensator now has real restart coverage, but this does
not qualify all upstream cleanup paths. Concurrent-process races, lost-ack and
process-crash matrices, full caller context, credential/security custody,
authenticated external start, independent executor claims and reports,
SDK/sidecars and every original launch gate remain required. No commit, push,
hosted CI rerun, workflow repin, merge, activation or publication occurred.

### Live operation-owned runtime admission and explicit activation

The next slice wires prepared runtime plans into live kernel dispatch through a
call-scoped, non-serializable claim authority. It adds the activation API but
does not activate a user database or qualify a release.

- The kernel chooses the durable operation, original request binding, matching
  grant, acquisition phase and unique episode. The trusted runtime verifier
  supplies only its complete prepared-plan digest and ordered resources. An
  Allow requires exactly one successful claim and exact physical history
  readback. Ignoring a claim error or attempting a second claim cannot authorize
  execution. Read-only tools also require durable ownership in this profile.
- The runtime plan binds actual bundle, treaty and swarm artifact bytes,
  verified request/route material and configured witness keys. Store-advertised
  treaty hashes are independently recomputed. The real trust-floor CAS remains
  mandatory; legacy replay writers and metadata-based release are excluded.
- Ordinary and nested grant fallback release the previous episode before
  preparing another grant. Positive budget authorization, capture and nonce
  preflight require the matching live grant and phase. Nonce issuance releases
  preflight custody; nonce presentation obtains a fresh dispatch episode.
- Denial, panic, source-barrier loss and pre-dispatch Drop route through physical
  operation ownership even without hook metadata. Store callback panics are
  caught before unwinding through the mutation sequencer. Dispatch commitment
  retains custody; terminal replay cannot reacquire resources or redispatch.
- Admission schema 21 adds an immutable third migration event for explicit
  activation. A pinned and imported source is insufficient. Activation verifies
  the actual sealed source outside the destination transaction, checks the
  owner fence and exact generation again, commits once, and reads back. Exact
  retries never repair or reseal damaged source barriers. Populated schema-19
  and schema-20 migrations preserve prior claim, release and global commit
  history. Operators must quiesce already admitted legacy work before activation.
- Runtime-core and facade expose the explicit profile without an implicit
  fallback. Unsupported source stores, a different physical source, inactive
  generations and fixed-clock overrides reject.

Concrete verification includes the 72-test runtime-admission suite, with live
SQLite dispatch, ordinary and nested fallback, nonce preflight/issuance/
presentation, terminal replay, Drop, trust-floor failure, verifier failure and
independently hashed artifact-tampering cases. The real source and destination
also close and reopen under a new serving owner after activation, reject the old
fence and preserve the exact three-event history. The complete SQLite library
suite passes 1,283 tests with zero failures and the same three existing ignored
entries (460.17 seconds under `umask 022`). Its parent test executes the
serving-owner child-process helper successfully.

The final kernel library run passes all 1,247 tests without ignores.
Runtime-core passes 262 tests and the runtime facade passes 15, also without
ignores. Two new kernel-port boundary tests exercise normal acquisition,
no-op success, replaced references, wrong operation acknowledgements, lost claim
acknowledgements, a panic after commit and a panic during history readback.
Even a verifier that swallows the error and returns Allow cannot dispatch;
the current operation and exact released history remain recoverable. These
fault doubles verify coordinator behavior, not physical SQLite atomicity or
process-crash durability.

The separate kernel durable-admission SQLite integration target passes all
11 tests. The caller-execution SQLite target passes 18 tests with its one
explicit external-start/lost-report contract still ignored; that ignored test
is an unimplemented boundary, not passing qualification.

Scoped all-target Clippy passes for kernel, SQLite, runtime-core and runtime
with warnings denied; xtask all-target Clippy also passes. Public-surface
policy, Rust file hygiene, workspace and explicitly included-test formatting,
formal mapping, Apalache slice contracts, whitespace checks and the security CI
contract pass. The CI contract's trust-boundary/evidence mutation tests pass.
Explicit WIP classification covers 285 individual files across 11 slices; the
commit-only check still sees zero files against unchanged HEAD. Cargo.lock is
unchanged during this slice. The final code-graph refresh completed with
160,722 nodes, 418,035 edges and 6,899 communities.

The formal review adds five required implementation anchors for operation-owned
acquisition, readback, release, plan commit and revalidation. All 78 mirrors match
after review; the 21 mirror tests pass, including independent removal of each
required symbol. Proof coverage remains 58 rows and 168 artifacts. The model
transitions, assumptions and bounds are unchanged. Aggregate lease conservation
does not prove the physical claim ledger, activation, cross-store CAS or
lost-acknowledgement recovery. Those boundaries require concrete tests, as
documented in `formal/MAPPING.md`.

Still open: full live destructive/treaty/swarm resource combinations across
failure and recovery phases, concurrent-process races and process-crash
qualification, full caller context and credential/security custody,
authenticated external start, independent executor claims and authenticated
reports, SDK/sidecars and every original launch gate. The ignored external
effect/lost-report contract is not implemented by this slice. No commit, push,
hosted CI rerun, workflow repin, merge, user-database activation or publication
occurred.

### Composed destructive, treaty and swarm runtime custody

The live ordinary dispatch path now has a combined fixture with a real sealed
runtime SQLite source, separate serving authority, signed treaty/lineage/DSSE
evidence, verified swarm capability and witness, authenticated peer handshake,
durable receipt log and bilateral receipt co-signing. It uses the production
runtime hook and kernel entrypoints. No verifier, physical claim or trust-floor
port is replaced by a successful test adapter.

Seven new regressions cover:

- Successful dispatch retains exactly the destructive lease, treaty
  continuation and swarm continuation. Terminal replay preserves the signed
  receipt and physical history without reacquisition or redispatch. Closing all
  owner handles and reopening under a new fence preserves that behavior and
  rejects the old fence.
- Verifier denial, panic and actual source-barrier removal happen after a
  confirmed three-resource claim. Every resource is released before
  compensation; a missing claim cannot make the regression pass.
- Nonce preflight releases all three resources before issuance. Presentation
  obtains a new dispatch episode, preserves the released predecessor and
  retains the complete set at commitment. Completed nonce replay does not
  dispatch again.
- Dropping the future during pre-dispatch readiness releases all three
  resources and compensates the operation. A tool error or post-dispatch Drop
  instead retains the complete set and the captured invocation. Restart,
  reconciliation and retry do not free the resources, refund the invocation or
  redispatch the uncertain effect.
- A historical imported marker of each kind independently rejects the entire
  live claim. The tests require the physical replay-conflict error, zero new
  episode/resource/release rows and preservation of the imported marker.
- A controlled overlap parks the first invocation with all three pre-dispatch
  claims. A different request reaches the physical conflict, denies without
  changing the first owner's history and leaves no partial claim. Cancelling
  that owner releases its set, allowing a third fresh operation to acquire and
  dispatch while preserving the released predecessor.

Local verification: all 79 runtime-admission tests pass. The complete
runtime-core suite passes 269 tests and the facade passes 15, without ignored
tests. All-target Clippy for kernel, SQLite, runtime-core and runtime passes with
warnings denied. All 78 formal mirrors match without blessing; the 21 mirror
regressions pass. Proof coverage was regenerated and checked at 58 rows and
168 artifacts. Formatting, public-surface policy, Rust file hygiene, formal
mapping, Apalache slice contracts, the static security CI contract and whitespace
checks pass. The CI contract's trust-boundary/evidence mutation regressions also
pass. WIP classification covers 288 files across 11 slices; the
commit-only check still sees zero files against unchanged HEAD. Cargo.lock is
unchanged during this slice. The final code-graph refresh completed with
160,769 nodes, 418,167 edges and 6,996 communities.

This is concrete runtime evidence, not a new theorem or full profile
qualification. Controlled task overlap is not an independent-process race;
close/reopen and Drop are not process-kill or power-loss tests. The full nested
three-resource, subset, interruption and lost-acknowledgement matrix remains
open, alongside caller context, credential/security custody, authenticated
external start, independent executor claims/reports, SDKs and every original
launch gate. No commit, push, hosted CI rerun, workflow repin, merge,
user-database activation or publication occurred.

### Combined runtime custody across worker process loss

Three new regressions now kill a real worker process while it holds a live
combined destructive/treaty/swarm evaluation. Each parent owns a private
temporary directory, launches only its exact integration-test worker, waits
for a bounded readiness signal and corroborates the boundary by reading the
committed physical authority and tool-side SQLite rows. The parent sends
SIGKILL to that specific child and reaps it. Assertion failures and timeouts
also reap the owned child before fixture cleanup. No evaluation future, kernel
or authority destructor runs in the killed worker.

The cuts and recovery assertions are:

- After the three-resource claim and budget authorization, before dispatch:
  process loss leaves the live claim and authorized hold unchanged. A new
  serving owner rejects the old fence, releases the complete resource set,
  physically reverses the invocation authorization and compensates the old
  operation. A fresh request acquires the same resource identities, commits a
  real tool-side effect and retains its own episode without changing the
  released predecessor. The fresh destructive bundle has a new request-bound
  digest; the treaty and swarm artifact digests remain unchanged.
- After entering the tool, before its effect: the physical dispatch commitment,
  captured invocation and all three resources survive termination. Recovery
  records outcome-unknown rather than inferring that no effect occurred. Both
  the old request retry and a fresh competing request cannot redispatch; the
  latter must reach the physical replay-custody conflict.
- After committing the tool-side SQLite effect, before returning its result:
  recovery preserves the effect, captured invocation and complete retained
  resource set. The durable tool-entry and effect counters remain exactly one
  across recovery and both retries. No refund or duplicate effect is accepted.

Every cut verifies unchanged operation/resource/budget state immediately after
the kill, validated history under the new fence, exact predecessor identity,
idempotent reconciliation, and a signed decision for the fresh request. These
are ordinary in-process tool dispatch tests with real process termination,
not an authenticated external caller/start/report transport. They do not model
arbitrary mid-transaction power loss or concurrent independent serving owners.

Local verification: all 82 runtime-admission tests pass, including the three
new parent-controlled process-loss tests. The complete runtime-core suite
passes 272 tests and the runtime facade passes 15, without ignored tests.
All-target Clippy for kernel, SQLite, runtime-core and runtime passes with
warnings denied. All 78 formal mirrors match without blessing; their 21
regressions pass. Proof coverage was regenerated and checked at 58 rows and
168 artifacts. The concrete crash cuts add runtime evidence, not new formal
transitions, assumptions or proved properties.

Formatting, public-surface policy, Rust file hygiene, formal mapping, Apalache
slice contracts, the static security CI contract and its trust-boundary/evidence
mutation regressions pass. WIP classification covers 291 individual files
across 11 slices; the commit-only check still sees zero files against unchanged
HEAD. Cargo.lock is unchanged during this slice. The final code-graph refresh
completed with 160,832 nodes, 418,294 edges and 6,975 communities. No production
Rust change was required by these three crash regressions.

The wider interruption/lost-acknowledgement and independent-process race matrix
remains open, as do authenticated nested combined dispatch, full caller context,
credential/security custody, external start, independent executor claims and
reports, SDKs and every original launch gate. The ignored external-effect and
lost-report contract remains unimplemented. No commit, push, hosted CI rerun,
workflow repin, merge, user-database activation or publication occurred.

### Typed caller return component at report-time capture

The existing caller-report path now produces a bounded, private
`chio.kernel-caller-return-context.v1` component before its dispatch capture.
This is the report-time boundary, not reservation or authorization before an
external effect. The component binds the original operation and request,
selected grant, frozen metadata and stream limits, pre-invocation guard
evidence, signing identity, security identity data, retained federation
evidence and the existing runtime participant ledger root.

The kernel uses the already-qualified caller capture port to retain this frame
atomically with quota capture and nonce dispatch commitment. It reloads the
exact canonical bytes under the serving-owner fence and decodes the typed
component before recording the report as a tool return. The decoder validates
size, schema, exact canonical encoding, identity, time, selected grant and
original request binding. Federation material goes through the existing
signature and participant-pin verifier. Receipt metadata, context presence or
a deserialized treaty DTO never substitute for that verification.

Local freeze rejection remains distinct from an unconfirmed store commitment.
Unsupported context stores, missing or changed readback and callback failures
deny without optimistic compensation. Capture and context-read callback panics
are caught before unwinding through the mutation sequencer. Recovery can
inspect the retained operation instead of assuming the write failed. Ordinary
and nested noncaller dispatch keep their existing in-memory return behavior,
without caller-frame size limits or extra context I/O. No new database schema,
external start API or executable permit was added.

New regressions cover:

- Three model-only codec tests exercise the actual producer and decoder,
  frozen facts after configuration change, private payload exclusions and
  substituted, noncanonical, oversized or unbound inputs. They do not claim
  physical storage qualification.
- A capture callback regression panics before and after commitment. Recovery
  after lease expiry remains callable and compensates only the uncommitted
  case; the committed case retains its invocation as outcome unknown.
- Three real SQLite/kernel tests exercise exact frame and signed receipt
  replay across restart, stale-owner rejection, live and startup schema-tamper
  refusal, and interruption after context capture but before report recording.
  The interruption uses unwinding and reopen, not a process kill. The schema
  test reaches the tamper fences, not an injected capture failure. Existing
  store-internal temporary-trigger regressions separately cover transaction
  rollback at context insertion and the subsequent nonce-history insertion.

Local verification uses Rust 1.94.1, offline dependencies and `umask 022`.
All 1,251 kernel library tests and 1,283 SQLite library tests pass (the latter
retains three existing ignores). Caller execution passes 21 tests with its
one explicitly open ignored contract; nonce lifecycle passes all 15 tests.
Kernel/SQLite integration passes all 11 tests. The complete runtime-core suite
passes 272 tests, including all 82 runtime-admission tests, and the runtime
facade passes all 15 tests; neither suite has ignored tests.
All-target Clippy for kernel, SQLite, runtime-core and runtime passes with
warnings denied, as does the kernel check with default features disabled.

All 81 reviewed formal mirrors match, including the new codec, fenced read,
capture and federation-verification anchors. All 21 mirror regressions pass.
Proof coverage was regenerated and checked at 58 rows and 168 artifacts. No
model transitions, assumptions or proof bounds changed, and these anchors do
not prove persistence or external execution. Formatting, public-surface policy,
Rust file hygiene, formal mapping, Apalache slice contracts, the static security
CI contract and its trust-boundary/evidence mutation tests pass. WIP
classification covers 298 individual files across 11 slices; the commit-only
check sees zero files against unchanged HEAD. Cargo.lock is unchanged during
this slice. The code-graph refresh completed with 160,879 nodes, 418,427 edges
and 6,961 communities.

The external-effect/lost-report contract was explicitly rerun and still fails
at the intended assertion: after the effect, report loss and nonce expiry,
observed quota and the next reservation are `((0, 0), Allow)` instead of
`((0, 1), Deny)`. It remains ignored in normal enumeration and is not counted
as a passing launch gate. A reservation must not authorize an external effect.

Complete credential/security-hook custody, authenticated start before the
effect, independently keyed executor permits and durable claims, authenticated
historical reports, SDK/sidecar integration and the wider runtime interruption,
nested and process-race qualification matrix remain open. All original native
platform, dependency audit, exact-candidate hosted CI, packaging, publication
and observed-pilot gates remain separate. No commit, push, hosted CI rerun,
workflow repin, merge, user-database activation or publication occurred.

### Non-consuming credential preparation

The shared credential path now has a kernel-bound preparation value separate
from replay-store acquisition. It borrows the same immutable request and
capability, validates the applicable DPoP, legacy execution nonce and governed
approval inputs, and queries nonce reservation support before any replay
write. Dropping the prepared value neither consumes nor releases a marker.
It is not cloneable or serializable and exposes no dispatch authorization.

Consuming preparation revalidates the same artifacts with fresh time. The
consumer cannot supply replacement inputs or a different kernel. A backend
that changes between owned-reservation and legacy semantics rejects before
mutation. The reservation-capability callback is now panic-contained and runs
before DPoP acquisition; an unhandled probe panic can no longer unwind after
an earlier credential has already been reserved. Actual acquisition still
uses the existing owner-qualified rollback and retention rules, including
legacy nonce deferral until the effect boundary. Preparation does not reserve
replay capacity or promise that a later acquisition will win contention.

The ordinary and nested dispatch entrypoints use this shared path. Caller
authorization also uses it while preserving its required governed approval
and absence of a presented execution nonce. Operation-owned nonces continue to
delegate custody to the qualified admission authority rather than acquiring a
second legacy marker. Existing forced post-reservation mutable-authority
revalidation remains in place.

Eight new regressions use complete signed requests with actual in-memory
replay stores and counting/fault adapters. They cover mutation-free preparation
and Drop, competing prepared attempts, exact approval-binding rejection,
nonce and approval expiry between phases, capability-probe panic in either
phase, changed backend semantics, consumed-approval partial rollback and caller
authorization without a presented nonce. Expiry and binding cases require the
intended denial rather than accepting an unrelated error. These are local
ordering and ownership tests, not durable storage or process-crash evidence.

The original credential module is reduced from 565 to 399 lines. Its separate
preparation and acquisition modules own the corresponding implementations;
retention, rollback and Drop remain together in the original module. No new
public protocol, database schema, profile activation or dependency was added.

This boundary precedes durable credential custody. DPoP remains process-local;
the separate governed approval store's reservation UUID is not an anchored
admission-operation owner. Security-hook request-lifecycle permits and outcome
recorders also still need operation-bound durable ownership. Complete
credential/security participants, legacy-consumer migration, authenticated
external start, independent executor claims/reports and every original launch
gate remain open. The new prepared value must not be accepted as a custody
certificate or substituted for the complete caller admission snapshot.

Local verification uses Rust 1.94.1, offline dependencies and `umask 022`.
All 1,259 kernel library tests pass, including the eight new regressions.
Caller execution passes 21 tests with its one open ignored contract, nonce
lifecycle passes all 15 tests, persistent governed approval replay passes all
16 focused SQLite tests, and kernel/SQLite integration passes all 11 tests.
The complete runtime-core and runtime suites pass 272 and 15 tests respectively;
all 41 security-kernel integration tests pass. These suites have no ignored
tests, and runtime admission includes the existing 82-test custody matrix.
The complete SQLite library suite was not rerun for this kernel-only change.
All-target Clippy for kernel, SQLite, runtime-core and runtime passes with
warnings denied; the final kernel test edits also pass all-target Clippy.
The kernel check with default features disabled passes.

All 85 reviewed formal mirrors match. Four new entries cover preparation and
acquisition under both dispatch abstractions; the existing parent entries now
also require caller authorization and the callback-containment helper. All
21 mirror regressions pass, including independent omission of every required
symbol. Proof coverage was regenerated and checked at 58 rows and 168
artifacts. No model transition, assumption or proof bound changed. Formatting,
public-surface policy, Rust file hygiene, formal mapping, Apalache slice
contracts, the static security CI contract and its trust-boundary/evidence
mutation tests pass. WIP classification covers 302 individual files across
11 slices; the commit-only check still sees zero files against unchanged HEAD.
Cargo.lock is unchanged during this slice. The graph refresh completed with
160,934 nodes, 418,521 edges and 6,956 communities.

The ignored external-effect/lost-report contract was rerun explicitly and
still fails at the intended assertion, `((0, 0), Allow)` versus
`((0, 1), Deny)`. This is retained evidence of missing authenticated start,
not a passing launch gate. No commit, push, hosted CI rerun, workflow repin,
merge, user-database activation or publication occurred.

### Governed approval legacy source sealing

The durable governed approval replay store now has an explicit source-retirement
boundary: preview a complete inventory, seal exactly that pinned expectation,
load its persisted seal and verify the current source against the expectation.
This is a migration prerequisite, not destination activation or operation-owned
credential custody. No configured user database has been sealed.

One immediate transaction compares the complete candidate before its first
write and installs the inventory with twelve persistent SQL mutation barriers.
It freezes every physically retained reservation and committed marker, expiry,
clock high-water, prune horizon and capacity. Sealing never prunes or rewrites
the inventory. Legacy unscoped-subject markers retain their cross-subject
blocking semantics; historical reservation IDs do not become operation owners.
WAL with synchronous FULL and exact post-commit SQLite readback are required.
Commit ambiguity must be resolved through load/verify, never legacy resumption.

Reserve, owner-qualified commit/rollback, clock recovery and startup paths now
exclude sealed sources. Typed writers reject even no-op mutations, while
persistent triggers block actual mutations from already-open old connections.
Sealed reopen validates before schema initialization, journal normalization,
clock advancement, pruning or capacity changes. Requested capacity is ignored
for a sealed read-only source. Incomplete or substituted evidence is refused
without repair. Every pooled connection now initializes synchronous FULL.

Canonical evidence is bounded to 16,384 markers, 512-byte identifiers and
8 MiB. Full-range integer fields use exact decimal strings. Storage types and
text sizes are checked before marker allocation; duplicate or unordered
decoded markers reject even with a recomputed digest. The exact protected SQL
catalog and barriers are committed, and the source binds its actual SQLite
file descriptor to the configured regular, single-link path. Copied files,
changed path identity, symlink/hardlink aliases, memory databases and unsupported
VFSes cannot qualify. Historical ALTER-created schema variants require separate
qualification rather than silent normalization.

The implementation separates the store transaction boundary, bounded evidence
codec, SQL catalog/barriers and inventory reader into focused modules. An opaque
seal can only result from live store verification; decoding yields data only.
Debug output omits marker and reservation identifiers. The source/authority
labels are operator configuration, not authenticated authority credentials.

All 34 focused approval replay tests pass, including 18 new regressions. The
new matrix covers populated reserved/committed/legacy inventories, exact retry
and read-only reopen, typed no-ops and old-connection writes, changed candidates,
four pre-commit SQL cutpoints, post-commit acknowledgement loss with reopen,
reservation/seal races, restored-barrier inventory tampering, malformed and
oversized data, copied/path-substituted sources and changed journal mode.
These are local real-SQLite and injected-error tests, not power-loss or native
independent-process crash qualification.

The first full SQLite run exposed a receipt-retention fixture race: the repaired
store was sampled immediately after reopen while its writer could still have
the intentionally fail-closed unseeded head. The test passed in isolation, but
its health assertion had no startup barrier. The idempotent-repair test now
awaits an actor flush before checking the complete health report, and the
neighboring fully-archived reopen test uses the existing bounded writer-readiness
helper. No production readiness or integrity check was weakened. Extracting
the repaired fixture into its own module also reduces the oversized retention
test file from 4,668 to 4,566 lines without raising its hygiene allowance.

Source sealing grants no new dispatch permission and cannot revoke work already
admitted. Legacy consumers must be quiesced. Independent destination expectation
pinning, conservative replay import, operation-fenced approval claims and their
activation remain open. DPoP still has a separate volatile replay-history gap;
an empty cache after restart cannot prove absence of prior consumption. Durable
security-hook custody, authenticated external start, independent executor claims
and reports, the ignored lost-report counterexample and all original operational
and release gates also remain open. No antirollback theorem is claimed. The
ignored external-effect/lost-report test was explicitly rerun and still fails
at the intended assertion, `((0, 0), Allow)` versus `((0, 1), Deny)`.

Final local verification uses Rust 1.94.1, offline dependencies and `umask 022`.
The complete SQLite library rerun passes 1,301 tests with three existing ignored
cases. The first full run had 1,300 passes and the fixture failure described
above; it is not counted as a green gate. The repaired fixture passes in
isolation, all 62 active retention tests pass, and both repaired reopen tests
pass ten additional repetitions each under concurrent full-suite load.
The complete kernel library passes 1,259 tests. Caller execution passes 21
with its one known ignored contract; nonce lifecycle passes 15, governed
approval kernel replay passes one, and kernel/SQLite integration passes 11.
These selected suites total 2,608 passing tests, without counting repeated
focused runs or the deliberately failing lost-report counterexample.

Kernel and SQLite all-target Clippy pass with warnings denied; the final
retention edits also pass SQLite all-target Clippy. The kernel check without
default features passes. All 85 formal mirrors match, and regenerated proof
coverage matches at 58 rows and 168 artifacts. No formal transition, assumption
or proof bound changed. Formatting, explicit included-test formatting,
public-surface policy, Rust file hygiene and their self-tests pass. Formal
mapping, Apalache slice contracts, the static security CI contract and its
trust-boundary/evidence mutation tests pass. WIP classification covers 313
individual files across 11 slices; the commit-only check still sees zero files
against unchanged HEAD. Cargo.lock is unchanged during this slice. The final
graph refresh completed with 161,043 nodes, 418,820 edges and 6,944 communities.

No commit, push, hosted CI rerun, workflow repin, merge, user-database activation
or publication occurred. Workspace-wide and exact-candidate release qualification
remain separate gates; this checkpoint does not authorize launch.

### Governed approval destination expectation and inactive import

The qualified admission store now independently pins a complete governed
approval replay source generation to its actual store UUID and the configured
approval authority. Exact sealing and live verification precede an atomic
import of every retained marker as unresolved blocking evidence. Expectation
and import each have an immutable local event and exactly one matching global
anchored commit, including their original owner fence. This advances the
credential migration prerequisite; it does not activate approval claims or
grant dispatch permission. No configured user source has been sealed or imported.

The kernel now owns the dependency-neutral, bounded canonical data codec and
the configured source port. Its byte format and digest domain are unchanged.
Snapshot construction or decoding proves data validity only; the SQLite seal
remains an opaque result of live source verification. Source callback panics
are contained, and callbacks run outside the destination database mutex and
transaction. Imports share an owner-wide nonblocking guard with runtime source
import and activation, including adapters obtained from the same owner.

The destination retains subject, request, intent, exact expiry, nullable
historical reservation identity, wildcard-subject semantics, source identity,
clock high-water, prune horizon and capacity. Legacy reservation IDs do not
become operation owners. Pending expectations reserve complete inventory
capacity before freezing a source: at most 128 sources, 64 MiB of canonical
source data and 65,536 markers overall, with the existing per-source bounds.
One physical source cannot be pinned under multiple bindings, and source and
destination must be different physical database files. Existing exact pins do
not rediscover the source; imported retry verifies live evidence without
resealing or writing another destination event. Failed SQL writes roll back;
lost seal acknowledgements preserve the original pin for exact recovery.

A restart hazard was fixed before qualifying this boundary. Normal legacy
startup may advance clocks and prune rows, invalidating a pending pin even if
no tool call occurs. `SqliteGovernedApprovalReplaySource::open` is a distinct,
migration-only handle that preserves an existing canonical source without file
creation, migration, clock advancement, pruning or capacity changes. It exposes
no legacy replay writer. Migration inspection now uses a read-only metadata
check instead of the shared startup helper that can adopt application IDs.
Ordinary sealed reopen also verifies evidence before that adoption helper, so
a cleared application identity cannot be silently repaired. Legacy consumers
must still be quiesced; changed unsealed inventory is refused, never repinned.

Admission schema v22 introduces only the empty approval migration namespace
after verifying its predecessor. Existing active runtime history is preserved.
Global schema migration recognizes only exact historical catalogs, preserves
all rows and digests, and rejects future projection kinds smuggled through a
disabled CHECK before changing any schema. Historical test fixtures explicitly
remove only empty newer namespaces; populated security history is never erased
to make a downgrade qualify. Global reference dispatch is extracted into its
own module, reducing the existing oversized parent without raising its cap.

The profile remains imported-inactive. Approval operation ownership,
operation-fenced release, activation and the imported clock/prune-horizon
handoff remain open. A future claim path must not revive previously pruned
credentials after clock rollback. DPoP still has distinct volatile-history
requirements. Full caller credential/security custody, authenticated start
before external effects, independent executor claims and authenticated reports,
the ignored lost-report contract, SDK/adapter integration and all original
operational, platform, supply-chain and release gates remain open. This is not
an antirollback theorem, a completed roadmap or launch authorization.

Seventeen new destination/source integration tests cover real SQLite inventory
preservation across pin/import/restart, subjectless markers, null and historical
reservation IDs, stale fences, changed candidates, duplicate physical bindings,
same-file refusal, pending capacity exhaustion, exact read-only retry, lost seal
acknowledgements, source panics, unlocked callbacks, reentry and concurrent
owner-wide exclusion. They also exercise expectation/tombstone/event/global
write cutpoints, local/global corruption independent of external-write
detection, immutable SQL guards, missing or damaged source metadata, changed
journal mode, missing source barriers and strict v21 migration. Two additional
tests preserve active runtime history through v22 and refuse future global
projection kinds injected with CHECK enforcement disabled. These are local
SQLite and injected-failure checks, not power-loss or native-platform crash
qualification.

The final complete SQLite run passes 1,320 tests with three existing ignored
cases, including the added sealed-metadata regression and stricter
duplicate-version-row refusal. The earlier complete run passed 1,319 tests.
The three ignored cases are the serving-owner child-process helper, opt-in
million-receipt scale proof and existing CI-wedging retention test, not passing
coverage. The complete kernel library passes 1,259 tests; kernel/SQLite
integration passes 11, caller execution passes 21 with its known ignored
lost-report contract, nonce lifecycle passes 15 and governed approval kernel
replay passes one. These selected suites total 2,627 passing tests, excluding
repeated focused runs and the earlier complete run. Kernel and SQLite all-target
Clippy pass with warnings denied, including a final SQLite check after metadata
hardening. The kernel check without default features passes. All 85 formal
mirrors match; regenerated coverage matches at 58 rows and 168 artifacts. No
formal transition, assumption or proof bound changed. Formatting, diff whitespace,
Rust public-surface policy, file hygiene and their self-tests, formal mapping,
Apalache slice contracts, static security CI checks and trust-boundary/evidence
mutation tests pass. The graph refresh completed with 161,226 nodes, 419,229
edges and 6,957 communities. All final verification commands have completed.

WIP classification covers 328 individual files across 11 slices, with none
unclassified. The commit-only review check still sees zero files against
unchanged HEAD `8b9f9243905dfa61acac82d83438684940777fe3`. Cargo.lock is unchanged
during this slice. No commit, push, hosted CI rerun, workflow repin, merge,
user-database activation or publication occurred. Workspace-wide and
exact-candidate release qualification remain separate gates.

### Governed approval operation ownership, clock handoff and recovery

Admission schema v23 adds explicit activation of an independently pinned and
imported approval source, plus operation-owned replay claims. Activation is an
immutable third migration event with an exact global commitment. The authority's
actual clock must reach the imported high-water and prune horizon before any
claim can be admitted; a caller timestamp ahead within tolerated skew cannot
substitute for that observation. Import alone remains inactive. Source callbacks
stay outside the destination lock and use the shared owner-wide migration guard.
No configured user source was activated.

Claims bind the original retained request and governed intent, selected grant,
preflight or dispatch phase, token digest, signer identity, signed validity
interval and exact imported authority generation. They carry no reusable token
signature. The first claim attaches a permanent operation ledger; subsequent
episodes append named commits without changing that ledger or operation version.
At most 128 episodes and one live owner are admitted. Every claim and release has
bounded canonical physical evidence in bijection with named admission commits
and the global anchored chain. Generic begin and compare-and-swap cannot invent
this ownership. Historical source reservation IDs never become operation leases.

Fresh claims, budget authorization and capture reject expired authority. The
freshness check runs after exact historical replay recognition; an already
committed authorization or dispatch acknowledgement is not a new use. Dispatch
history validates approval at its retained commit observation, also preventing
expiry between the pre-write check and commit append from leaving a committed
dispatch. Releasing an old episode cannot release its successor. A current
pre-dispatch lease can release expired ownership, but dispatch commitment
permanently forbids release, including restart or an absent execution report.
Expired scoped and wildcard legacy markers remain spent. Expiry frees live
capacity for different identities without deleting historical evidence.

Kernel startup compensation and nonce issuance now release exact retained
approval ownership through the store ports. They validate bounded history and
read back the exact release disposition. No token lookup or current signer
preparation participates in cleanup; store callback errors and panics remain
unresolved rather than evidence of release. Recovery does not grant execution.

The migration preserves v22 source bytes, fences, digests and admission history
and introduces only empty claim tables. Unqualified claim namespaces, premature
activation rows and damaged predecessor catalogs reject without repair. The
older v20/v21 migration definitions now name their historical admission DDL,
not newly added approval commit kinds. Fixture table reconstruction preserves
parent references rather than allowing SQLite to rewrite unrelated triggers.

Sixteen new regression tests cover real source activation and clock handoff,
original provenance and generation rejection, exact retry and successor release,
stale leases, expiry and capacity, permanent wildcard/scoped markers, SQL
cutpoint rollback, corrupted bounded history, post-dispatch retention, v22
migration, real combined budget authorization/capture, and kernel restart
compensation for both preflight and dispatch claims. These are local SQLite
and injected-failure checks, not independent-process power-loss qualification.

Normal configured verifier acquisition is still open. The next integration must
route completely prepared credentials into these claims without also consuming
the sealed legacy approval store, retain operation updates across a lost claim
acknowledgement, and exercise ordinary, nested and preflight routes together.
Acquisition belongs to the selected-grant admission episode before its budget
authorization. Replacing only the later dispatch credential reservation would
leave the initial budget authorization outside approval custody. Grant fallback
must release the preceding exact episode before claiming a successor; later
credential reservation must verify existing ownership rather than consume the
legacy marker or create a second claim. Complete non-consuming credential
preparation must precede that episode's first credential mutation.
Decoded claim data is not signer trust, a live lease or dispatch permission.
DPoP volatile-history migration, full caller credential/security-hook custody,
authenticated external start, independent executor claims/reports, the ignored
lost-report contract, SDK/adapter integration and every original platform,
supply-chain, pilot and release gate remain open. This checkpoint is not full
caller custody, an antirollback theorem, roadmap completion or launch authority.

Final serial validation on this checkpoint's source passed 1,336 SQLite library
tests (three existing ignored), 1,259 kernel library tests, 11 kernel SQLite
integration tests, 21 caller-execution tests (the external-start/lost-report
contract remains ignored), 15 execution-nonce lifecycle tests and one governed
kernel replay test. That is 2,643 passing tests across the selected suites,
excluding focused reruns and the subprocess helper's duplicate execution.
The 15 focused approval claim tests and 12 schema tests also passed. An earlier
full run exposed the corrected historical schema definitions; a subsequent
overlapping Cargo rebuild invalidated a running subprocess fixture by replacing
its executable. The final run was serial, with the subprocess fence case passing
both in isolation and inside the full SQLite suite. Failed runs are not counted
as qualification.

Strict all-target Clippy passed for `chio-kernel` and `chio-store-sqlite`, and
the kernel no-default-features check passed. Formatting, diff whitespace,
public-surface policy and Rust file hygiene passed without relaxing allowances.
All 85 formal mirrors match without blessing changed models. Proof coverage was
regenerated and checked at 58 rows and 168 artifacts. Formal mapping, the
Apalache slice static contract, security CI static contract and their applicable
mutation/self-tests passed. These checks do not claim new model-checker or
workspace-wide qualification. The final code graph refresh completed with
161,400 nodes, 419,826 edges and 6,968 communities.

WIP classification covers 340 individual files across 11 slices, with none
unclassified. The commit-only review check still sees zero files against
unchanged HEAD `8b9f9243905dfa61acac82d83438684940777fe3`. Cargo.lock is unchanged
during this slice. No commit, push, hosted CI rerun, workflow repin, merge,
user-database activation or publication occurred. Exact-candidate release
qualification and the full remaining roadmap stay open.

### Configured approval acquisition on normal kernel routes

`set_operation_owned_governed_approval_source` now selects an already activated
generation and its actual sealed source. It performs no import, activation or
history reset. Invalid reconfiguration leaves the installed authority unchanged.
Presented single approvals force structured admission with the original request,
including read-only grants outside the default side-effecting profile. Complete
non-consuming credential preparation precedes replay mutation. Normal and nested
grant selection acquire approval custody before budget authorization; fallback
releases the exact preceding episode. Later credential reservation verifies the
same kernel, original request, grant and token commitment without a second claim
or a legacy replay-store call. Preparation and post-readiness revalidation verify
the source outside the coordinator sequencer. Recovery requires no source callback.

Claim acknowledgements are checked against the operation transition and exact
physical history. Callback errors and panics cannot turn a committed claim into
an Allow; confirmed operation versions are retained for cleanup, including a
failed history callback after a valid acknowledgement. Release readback must
confirm the exact episode disposition. Dropping an old reservation cannot release
a successor. An unknown callback outcome stays denied rather than inferring
successful release or execution authority from a reference.

The nonce boundary now distinguishes a live single-approval claim from a
threshold set. Single custody is accepted only without a retained proposal/set
binding and after fresh physical ownership verification. Existing threshold
proposals still require their exact verified set. Oversized proposal storage now
fails closed rather than being interpreted as an absent proposal. Preflight
releases its approval episode before issuance; execution acquires a new episode.

The prior checkpoint's normal-acquisition gap is implemented by this slice;
the historical verification counts above apply to that earlier checkpoint only.
Full combined runtime/credential interruption and independent-process
qualification, DPoP migration, full caller security context, authenticated
external start and reports, SDK/adapters, platform and supply-chain qualification,
observed pilot and publication gates remain open. None is implied by the new
configuration API or by successful local tests. No user database was activated.

Final serial validation passed 1,347 SQLite library tests (three existing
ignored), 1,265 kernel library tests, 11 kernel SQLite integration tests,
21 caller-execution tests (the external-start/lost-report contract remains
ignored), 15 execution-nonce lifecycle tests and one governed kernel replay
test. These selected suites contain 2,660 passing tests, excluding focused
reruns and the subprocess helper's duplicate execution. This slice added six
kernel tests, ten real SQLite route tests and one oversized-proposal regression.
Coverage includes exact claim/release acknowledgement failures, original
request and kernel binding, grant fallback, source verification failure,
ordinary/session preflight and execution, nested dispatch, and cancellation
before and after the durable effect boundary. Adversarial port doubles test
coordinator behavior; they do not qualify SQLite power-loss behavior or the
remaining combined-credential and independent-process fault matrix.

Strict all-target Clippy passed for `chio-kernel` and `chio-store-sqlite`, and
the kernel no-default-features check passed. Formatting, diff whitespace,
public-surface policy and Rust file hygiene passed without relaxing allowances.
All 89 formal mirrors match after review and regeneration of 16 source anchors;
the checker ran 21 passing unit tests. Formal mapping and its regression tests,
the Apalache slice static contract, security CI static contract and its mutation
tests, and public-surface self-tests passed. The mapping test fixture was repaired
to include the second required Kani source and now tests its omission explicitly.
The model update is commentary only: no transition, assumption or bound changed,
and no new model-checker qualification is claimed. Proof coverage was regenerated
and checked at 58 rows and 168 artifacts. The final code graph refresh completed
with 161,535 nodes, 420,219 edges and 6,980 communities.

WIP classification covers 350 individual files across 11 slices with none
unclassified. The commit-only review check still sees zero files against
unchanged HEAD `8b9f9243905dfa61acac82d83438684940777fe3`. Cargo.lock is unchanged
during this slice. No commit, push, hosted CI rerun, workflow repin, merge,
user-database activation or publication occurred. Full-workspace and exact-head
release qualification remain open, as does the full remaining roadmap.

### DPoP volatile source retirement

The process-local DPoP cache now has a one-way retirement boundary exposed from
the kernel's actual configured source. It freezes canonical, bounded inventory
under the same mutex as insertion, dispatch reservation and rollback. A checked
mutation revision detects an intervening insert/rollback cycle. Exact retry and
live verification compare both the seal and physical state; neither reconstructs
the source from caller-supplied data. A replacement cache cannot verify a pinned
predecessor, including an empty predecessor. Legacy mutation and kernel DPoP
preparation/revalidation reject after retirement.

The inventory preserves physically retained expired markers, outstanding owners,
inclusive signed horizons, indefinite overflow, local-only TTLs, both replay
clocks, pruning history and capacity limits. Monotonic offsets are relative to
the live instance, not restart-portable time. No migration may replace them with
wall-only expiry or treat unknown history as unused credentials. Preview does
not prune or repair clocks; anomalies, oversize data and stale inventory refuse.
Operator namespace labels do not authenticate a new authority or prove absence
of earlier writers. Source retirement is not a stop-the-world dispatch barrier;
operators still need quiescence and an expected-source pin before cutover.

Durable expectation registration, import/activation, operation-owned DPoP claims,
recovery, composed credential faults, full caller security custody, authenticated
external execution and every original platform, supply-chain, pilot and release
gate remain open. The legacy DPoP setter remains process-local configuration,
not automatic restart-safe activation. No source or user database was migrated.

The oversized-inventory regression also characterizes an existing admission
resource gap: legacy `DpopNonceStore` bounds marker count, but clones nonce and
capability text without a byte bound. Export now refuses over-bound identities
without resetting them; it does not yet prevent their original admission. Close
runtime identity/byte admission and its stateless preparation boundary before
qualifying the durable DPoP profile. Preserve historical rejection behavior at
export rather than truncating or rehashing stored identities during migration.

Local verification passed all 35 focused DPoP tests, including 17 new source,
canonical-data and kernel preparation regressions. The final serial Rust run
passed 1,282 kernel library tests, 11 kernel SQLite integration tests, 1,347
SQLite library tests, 21 caller-execution tests, 15 execution-nonce lifecycle
tests and one governed kernel replay test. This is 2,677 passing tests across
the selected suites, excluding focused reruns and duplicate subprocess-helper
execution. Three existing SQLite tests remain ignored in ordinary enumeration;
the caller external-start/lost-report contract remains explicitly ignored.
No ignored case is counted as passing coverage.

Strict all-target Clippy passed for the kernel and SQLite crates, as did the
kernel no-default-features check, formatting, diff whitespace, Rust file hygiene
and public-surface policy. Formal mapping, the Apalache slice static contract
and security CI static contract passed. All 89 formal mirrors match without
new blessing. The initial proof-coverage check correctly detected a changed
input digest; the report was regenerated and rechecked at 58 rows and 168
artifacts. No model, theorem or proof assumption changed, and no new formal
model-checker qualification is claimed. The code graph refresh completed with
161,626 nodes, 420,484 edges and 6,978 communities.

WIP classification covers 355 individual files across 11 slices with none
unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`, and
Cargo.lock is unchanged during this slice. No commit, push, hosted CI rerun,
workflow repin, merge, user-source activation or publication occurred.
Full-workspace and exact-candidate release qualification remain open; this
checkpoint is neither complete DPoP custody nor full roadmap completion.

### Bounded DPoP identity admission and complete sender retention

The prior checkpoint's replay-key resource gap is closed for the shipped Rust
kernel and remote MCP sender paths. All nonce, binding and reservation identity
parts are bounded to 4,096 UTF-8 bytes before key allocation or replay mutation.
Non-consuming proof validation shares the key check before canonicalizing the
signed body. Oversized identities cannot advance the source revision, consume
another credential or erase retained history. Valid identities are never trimmed,
normalized or truncated, and failure messages do not echo their text.

A separate 16 MiB default retained-identity budget complements the marker limits.
Hosts can explicitly tune it through `new_with_identity_byte_capacity` and observe
it through `identity_byte_utilization`. The checked charge includes nonce and
reservation-owner text plus two capability copies per marker to conservatively
cover the count index. It is not a whole-process memory cap; container overhead
is bounded by the independent marker limit. Admission, expiry reclamation and
exact-owner rollback update accounting under the cache's existing mutex. Byte
pressure cannot evict a live marker or release a competing reservation. The
sealed source inventory binds the byte limit and recomputed exact charge;
substitution or accounting mismatch refuses verification. Historical oversized
inventory remains a refusal case, not an import truncation or reset path.

The writer audit also found remote MCP sender proofs using local-TTL replay
retention despite accepting future-dated proofs within clock skew. That could
forget an accepted nonce before its signed validity ended. The actual sender
verifier now validates bounded identities and inserts through the inclusive
signed horizon. A zero-fallback-TTL regression characterizes the old replay path
and verifies that the signed writer still rejects the second presentation.

Durable expected-source registration and conservative import/activation are the
next DPoP boundary. Operation-owned DPoP claims and recovery, composed credential
faults, full caller security custody, authenticated external start/reports and
all original platform, supply-chain, observed-pilot and release gates remain
open. Count/byte admission and source sealing do not establish restart safety.

The focused run passed 43 kernel DPoP tests, 13 direct DPoP integration tests and
three remote sender regressions. This slice added 13 tests: seven cache/identity
cases, one kernel preparation case, two direct verifier cases and three remote
sender cases. The final serial run passed 1,290 kernel library tests, 13 direct
DPoP tests, six admission-equivalence tests, four formal-projection tests, 11
kernel SQLite integration tests, 57 remote-MCP library tests, 1,347 SQLite
library tests, 21 caller-execution tests, 15 execution-nonce lifecycle tests and
one governed kernel replay test. These selected suites total 2,765 passing tests,
excluding focused reruns and duplicate subprocess-helper execution. Three
existing SQLite cases remain ignored in ordinary enumeration; the caller
external-start/lost-report contract also remains ignored. No ignored test is
counted as passing coverage.

Strict all-target Clippy passed for the kernel, SQLite and remote-MCP crates,
as did the kernel no-default-features check, formatting, diff whitespace,
Rust file hygiene and public-surface policy. Formal mapping, the Apalache slice
static contract and the security CI static contract passed. All 89 formal mirrors
match without new blessing. Proof coverage was regenerated and checked at 58
rows and 168 artifacts; no theorem, model or proof assumption changed, and no
new model-checker qualification is claimed. The code graph refresh completed
with 161,658 nodes, 420,566 edges and 6,908 communities.

WIP classification covers 361 individual files across 11 slices with none
unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`, and Cargo.lock
is unchanged during this slice. No commit, push, hosted CI rerun, workflow repin,
merge, user-source activation or publication occurred. Full-workspace and
exact-candidate release qualification remain open, along with the full roadmap.

### Durable expected DPoP source and imported-inactive history

The qualified SQLite admission store now pins the actual process-local DPoP
source instance under an independently configured DPoP authority and the exact
destination serving-owner fence. The expectation binds the complete canonical
source inventory. A retry reads that immutable expectation; it cannot repin a
changed source or substitute an empty replacement cache.

Import seals and verifies the live, exact source outside the destination mutex
and transaction. The destination then atomically retains every canonical marker,
the import event and its global authority-chain commitment. Local and signed
deadlines, overflow retention and historical reservation owners remain data.
Process-relative clocks are not translated into portable expiry, and historical
owners do not become releasable operation custody. A lost seal acknowledgement
leaves the destination pending and the source sealed; exact retry can finish
the same import. Once imported, retry verifies the source without resealing or
reconstructing it. A missing or replacement source denies import and retry.

The new three-table family is immutable, rejects INSERT OR REPLACE even with
recursive triggers disabled, and has bounded row, identity and blob sizes.
Aggregate limits are 128 source generations, 64 MiB of canonical source data
and 65,536 retained markers; pending expectations reserve inventory capacity
before sealing. Tombstones have their own bounded canonical representation and
64 MiB aggregate byte ceiling. Readback checks exact source bindings, event
digests, historical leases, complete marker equality and a one-to-one match
between local events and global references. Damaged history is not repaired.

Admission schema version 24 introduces only an empty DPoP namespace on upgrade.
The preceding catalog and populated approval custody are verified before
migration. The version-23 migration is no longer reapplied to a version-23
database. Historical global-commit catalogs gain the new projection kind only
through exact predecessor matching, without rewriting historical row digests or
the authority baseline. Historical test fixtures remove only demonstrably empty
new tables; they never erase populated replay history to simulate an upgrade.

The behavioral suite adds real-source pin/import/retry, destination reopen,
source replacement and mutation, stale fences and generation mismatches,
authority-clock regression, source unavailability and panics, lost seal
acknowledgements, reentrant and concurrent import, destination write cutpoints,
immutable guards, altered rows and global references, pre-decode storage
bounds, and refusal to repair damaged or unqualified schemas. A populated
version-23 upgrade also retains active approval authority and owned claims.
Synthetic undecodable blobs appear only in negative storage-bound tests, not
as evidence of a qualified source backend.

This is an imported-inactive migration boundary, not DPoP serving activation.
It does not establish continuity with an unknown prior process or authority.
Authenticated authority creation/rekey or refusal of unknown history, portable
retention semantics, operation-owned DPoP claims and recovery, full caller
credential/security-hook custody, authenticated external start and canonical
executor reports remain required. The complete roadmap, native platform,
dependency-audit, pilot and release gates remain open. No user source was
activated, and no commit, push, hosted CI rerun, workflow repin, merge or
publication is authorized by this checkpoint.

Final serial local verification with Rust 1.94.1 passed 1,290 kernel library
tests, 13 direct DPoP tests, six admission-equivalence tests, four
formal-projection tests, 11 kernel/SQLite integration tests, 1,368 SQLite
library tests, 21 caller-execution tests, 15 execution-nonce lifecycle tests and
one governed kernel replay test. These selected suites total 2,729 passing
tests, including all 21 new regressions and excluding focused reruns and
duplicate subprocess-helper execution. Three existing SQLite cases and the
caller external-start/lost-report contract remain ignored in ordinary
enumeration. No ignored case is counted as passing coverage. The initial
zero-match filter was corrected; two negative test fixtures were corrected to
exercise the intended storage bound and actual authority-clock regression.

Strict all-target Clippy passed for the kernel and SQLite crates, as did the
kernel no-default-features check, formatting, diff whitespace, Rust file
hygiene and public-surface policy. Formal mapping, the Apalache slice static
contract, security CI static contract and mapping/hygiene/public-surface
self-tests passed. All 89 formal mirrors match without new blessing. Proof
coverage was regenerated and checked at 58 rows and 168 artifacts; no theorem,
model or proof assumption changed, and no new model-checker qualification is
claimed. The final code graph refresh completed with 161,807 nodes, 420,966
edges and 6,973 communities.

WIP classification covers 374 individual files across 11 slices with none
unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`, and Cargo.lock
is unchanged during this slice. Changes remain uncommitted. Full-workspace and
exact-candidate hosted/release qualification remain open, along with the full
roadmap.

### Explicit DPoP proof domain and durable activation

The new `chio.dpop_proof.v2` profile signs an explicit replay-authority domain:
the canonical destination store UUID, independently configured authority name,
exact imported source generation, inclusive proof TTL and future-clock skew.
Validated bounded Rust types reject malformed identities, noncanonical or nil
UUIDs, unknown fields and out-of-range policies. The verifier selects its
expected domain independently of the proof and returns opaque, non-consuming
cryptographic evidence. That evidence cannot be decoded or cloned into an
operation claim and is not an activation credential or dispatch permit.

Legacy v1 signing retains the original eight-field canonical preimage. The
legacy Rust kernel and remote sender reject v2 and reject a non-null authority
attached to v1, including a correctly resigned downgrade. All five v2 domain
fields are signed and checked against the configured expectation. A proof
cannot cross domains by changing its schema or replay-authority fields. Shared
binding and signature checks remain mandatory; a pre-Unix system clock now
denies instead of being treated as epoch zero. V2 has immutable bounded
freshness and rejects proof horizons outside the durable clock range.

Admission schema version 25 adds a bounded, immutable activation descriptor
and a third DPoP migration event. First activation requires the actual source's
complete imported-inactive history, live exact retirement verification and a
destination clock no earlier than the conservatively rounded source wall-clock
high-water mark. Source callbacks run outside destination locks; the common
migration guard prevents overlapping or reentrant migration. The exact domain,
activation event and global authority commitment are written atomically under
the current owner fence. Partial writes roll back, and readback verifies the
same source generation, policy and anchored history.

After committed activation, exact durable readback and retry no longer consult
the retired volatile source. Destination reopen can recover that committed
domain even when the original source has been destroyed. This exception does
not apply to a pending expectation or imported-inactive source, which cannot
activate from a replacement. Legacy markers and their canonical retention
history remain unchanged. No process-relative expiry is translated, no legacy
proof enters v2, and no unknown earlier history is asserted to be empty. This
is a signed domain transition, not a capability-authority key rekey or a
general-purpose recovery path for lost volatile history.

Version-24 upgrades verify the exact preceding catalog and populated history,
preserve existing import/event digests and create no activation automatically.
Unknown activation namespaces and damaged predecessor schemas refuse upgrade
without stamping version 25. Activation guards reject replacement, update and
deletion even without recursive triggers. Invalid or altered canonical policy
is rejected by local/global verification and destination reopen.

TypeScript and C++ expose explicit v2 signing entrypoints while keeping legacy
signers on v1. A deterministic public-test-seed fixture checks the same canonical
body, signature and signed-proof digest across Rust, TypeScript and C++ (the C++
signer uses Rust FFI crypto). TypeScript authority padding follows Rust's Unicode
White_Space predicate instead of JavaScript's broader `trim()` behavior; SDK
tests retain exact non-padding names without normalization. No
signing helper establishes activation or replay custody. CMake now uses the
same explicit Cargo target directory for Rust build commands and FFI link
paths, including untyped relative command-line options resolved before CMake's
PATH-cache conversion. Six configure-only regression cases cover defaults,
typed/untyped relative paths, environment selection, explicit overrides and
absolute paths containing spaces. Equivalent C++ default member initializers permit strict warning
qualification without suppressing warnings. The CLI policy integration test
now imports the actual control-plane public API instead of compiling its
private source/test tree under the wrong crate root.

Operation-owned DPoP claims, fenced reserve/release/commit/recovery ports,
budget and nonce-preflight integration, configured kernel serving routing,
full caller credential/security-hook custody, authenticated external start
and canonical executor reports remain required. The v2 stateless helper and
SQLite activation API do not authorize execution today. The full security
roadmap, native platform, dependency audits, pilot and release gates remain
open. No user source was activated, and no commit, push, hosted CI rerun,
workflow repin, merge or publication was performed for this checkpoint.

Final serial local verification with Rust 1.94.1 passed 1,303 kernel library
tests, 13 direct DPoP tests, six admission-equivalence tests, 11 kernel/SQLite
integration tests, four formal-projection tests, 58 remote MCP library tests,
the CLI public-policy integration test, three control-plane swarm-policy tests,
1,376 SQLite library tests, 21 caller-execution tests, 15 execution-nonce
lifecycle tests and one governed kernel replay test. These selected suites total
2,812 passing tests, including 22 new Rust regressions. Focused reruns and the
duplicate serving-owner subprocess-helper execution are not counted again.
The SQLite suite completed in 810.89 seconds. Three existing SQLite cases and
the caller external-start/lost-report contract remain ignored in ordinary
enumeration; none is counted as passing evidence.

Strict all-target Clippy passed for `chio-kernel`, `chio-store-sqlite`,
`chio-mcp-remote`, `chio-api-protect`, `chio-conformance`, `chio-acp-edge`,
`chio-cli`, `chio-finding-hosted-edge` and `chio-control-plane`. The kernel
no-default-features check also passed. All 114 TypeScript SDK tests and its
type check passed. The C++ SDK passed a fresh-FFI-backed build with
`-Wall -Wextra -Werror` and both CTest groups, including the six configure-only
target-directory cases. No dependency, warning gate or allowlist was relaxed.

Formatting, diff whitespace, Rust file hygiene, public-surface policy, formal
mapping, the Apalache slice static contract and security CI static contract
passed, as did the mapping/hygiene/public-surface self-tests. All 89 formal
mirrors match without new blessing. Proof coverage was regenerated and checked
at 58 rows and 168 artifacts. No theorem, model or proof assumption changed;
these consistency checks are not new model-checker qualification. The final
code graph refresh completed with 161,924 nodes, 421,257 edges and 6,961
communities.

WIP classification covers 402 individual files across 11 slices with none
unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`; Cargo.lock
is unchanged during this slice. Changes remain uncommitted in the isolated
launch worktree. Full-workspace and exact-candidate hosted/release qualification
remain open, along with the full roadmap. This checkpoint qualifies the local
proof-domain and activation boundary, not complete DPoP replay custody or
launch readiness.

### Operation-owned DPoP custody

Admission schema version 26 adds physical operation-owned v2 DPoP claims,
immutable resource projections and exact pre-dispatch release history. Every
claim and release shares the admission transaction, exact-version recovery lease
and global authority commit chain. First custody advances the operation version;
later mutations must renew its lease. A lost acknowledgement reads the committed
version and exact reference instead of reacquiring authority. An old episode
cannot be reused or release its successor. Dispatch commitment permanently
prevents release, including after proof expiry, source loss and destination reopen.

The credential contract consumes opaque cryptographic verification output into
bounded, signature-redacted commitments. The proof digest and invocation digest
bind the exact capability ID/subject, target and action, while claim intent binds
the retained request, grant, phase and independently activated authority. Decoded
history is not signature verification, current policy, a configured authority or
an operation lease. Storage independently checks retained invocation and physical
ownership; the trusted configured kernel must supply fully verified intent.
That kernel acquisition and serving integration is the next required boundary,
not implementation already supplied by these ports.

Fresh budget authorization, real nonce-preflight authorization, invocation
capture and dispatch require unexpired live custody at the authority clock.
Already committed authorization/capture retries and historical recovery remain
available after expiry without granting fresh authority. Preflight custody must
be explicitly released before nonce issuance. Generic commands cannot introduce
a custody attachment without the atomic physical participant. Preflight and
issuance validation preserve the additional attachment and historical snapshots.

V2 live count, per-capability and logical identity-byte limits inherit the pinned
source policy. Legacy-domain tombstones remain permanent evidence but do not
occupy the distinct v2 live budget. Expiry frees live capacity, not unreleased
replay identity or spent history. Canonical claim/release records are bounded to
65,536 bytes, operation snapshots to 262,144 bytes and episodes to 128 per
operation. These limits do not claim a whole-database retention bound.

The migration verifies the exact preceding catalog and populated authority
history, rejects unknown pre-v26 custody, preserves existing admission/global
digests and does not activate or adopt claims. Predecessor test fixtures now
preserve dependent trigger names while rebuilding the commit table, matching
production migration behavior. Older populated fixtures may already own the
rebuild transaction; the shared fixture helper requires parent-name-preserving
settings in that case instead of assuming autocommit or changing a no-op PRAGMA.
SQL cutpoints leave no partial claim, resource,
release or global commitment. Corruption and overbound canonical storage deny
readback. Immutable guards reject replacement, update and deletion even with
recursive triggers disabled.

Focused validation passed three new kernel credential tests and all 47 SQLite
DPoP tests, including 19 new custody regressions. Real budget/preflight/capture
tests distinguish fresh authority from historical retry; a controlled two-thread
contention test leaves exactly one physical replay owner. State-machine-only
fixtures are labeled separately from physical budget tests. This is not an
independent-process race or crash qualification.

Final serial local validation with Rust 1.94.1, offline dependencies and
`umask 022` passed 1,306 kernel library tests, 13 direct DPoP tests, six
admission-equivalence tests, 11 kernel/SQLite integration tests, four
formal-projection tests, 1,395 SQLite library tests, 21 caller-execution tests,
15 execution-nonce lifecycle tests, one governed kernel replay test and 58 remote
MCP library tests. These selected suites total 2,830 passing tests, including
the 22 new regressions. Focused reruns and the duplicate serving-owner child
helper execution are not counted again. The final SQLite library suite used
two test threads and completed in 851.35 seconds. Three existing SQLite cases
and the caller external-start/lost-report contract remain ignored in ordinary
enumeration; none is counted as passing evidence.

Strict all-target Clippy passed for `chio-kernel`, `chio-store-sqlite`,
`chio-mcp-remote`, `chio-api-protect`, `chio-conformance`, `chio-acp-edge`,
`chio-cli`, `chio-finding-hosted-edge` and `chio-control-plane`. The kernel
no-default-features check also passed. No warning gate or allowlist was relaxed.
Formatting, diff whitespace, Rust file hygiene, public-surface policy, formal
mapping, the Apalache slice static contract and security CI static contract
passed, along with mapping, hygiene, public-surface and security-CI mutation
self-tests. All 89 formal mirrors match without new blessing. Regenerated proof
coverage matches 58 rows and 168 artifacts. These consistency checks are not
new theorem or model-checker qualification; no proof assumption was changed.
The final code graph refresh has 162,102 nodes, 421,864 edges and 7,022 communities.
Proof wire/signing and SDK sources are unchanged in this slice; SDK runtime
tests were not rerun, and their preceding checkpoint remains separate evidence.

Next implementation must connect independently configured activation to the
kernel's consuming credential preparation, normal/nested/preflight acquisition,
exact rollback and recovery. The combined preparation must retain origin/request
binding and must never fall back to the retired legacy cache. Full caller
credential/security-hook custody, authenticated external start and executor
claims/reports, combined interruption/process-crash matrices and SDK/client
migration remain open. The full original roadmap, native platform evidence,
dependency audits, observed pilot and release qualification also remain open.

No user source was activated and no commit, push, hosted CI rerun, workflow
repin, merge or publication was performed. Work remains in the isolated launch
worktree. WIP classification covers 418 individual files across 11 slices with
none unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`, and
the existing Cargo.lock is unchanged during this slice. Full-workspace and
exact-candidate hosted/release qualification remain open. This checkpoint
qualifies local physical DPoP custody, not complete kernel serving or launch
readiness.

### Configured DPoP kernel acquisition and recovery

The kernel now exposes explicit `set_operation_owned_dpop_authority` selection
of an already activated v2 domain through the qualified durable runtime. It
checks the complete descriptor and destination fence. Selection cannot import,
activate, reset or reconstruct the volatile source, and a configured domain
cannot be replaced on that kernel. Neither a subsequently installed legacy
cache nor a v1 proof can downgrade it. Deployment authentication and source
activation remain separate operator responsibilities.

Every matching DPoP-required grant under this profile forces structured durable
admission and retention of the original request, including read-only tools.
Non-consuming preparation validates all applicable credentials before any claim.
The consuming handoff binds the originating kernel, immutable request, selected
grant and exact preflight/dispatch episode. Each participant acquires its own
lease against the updated operation version. DPoP is claimed before budget
authorization and before a composed governed-approval claim. Reservation checks
the exact live claim and refreshes proof/domain validation; no reusable proof
signature enters retained custody data.

A claim callback can commit and then lose its acknowledgement or panic. The
coordinator reads back the authoritative operation and history before cleanup,
retaining any independently confirmed successor. Missing or inconsistent
acknowledgements deny. If both acknowledgement and history fail, it does not
invent an operation version; later authoritative recovery must establish one.
RAII and grant-fallback cleanup release only exact pre-dispatch episodes. Nonce
issuance releases its preflight claims. Startup cleanup uses retained history
after proof expiry and source loss, without configuring a new serving domain.
A committed dispatch remains spent across kernel/store reopen, even when the
caller supplies a fresh signature for the same replay identity.

The focused tests exposed and fixed missing original-request retention on
ordinary DPoP admission. Eight adversarial kernel tests and twelve real SQLite
route tests pass. They cover nested acquisition, no-op callbacks, wrong successor
or reference returns, acknowledgement loss and panic, missing readback, foreign
prepared kernels, request/grant substitution, exact-release confirmation, stale
RAII owners, explicit activation selection, legacy exclusion, invalid proof
variants, budget denial, grant fallback, nonce preflight, cancellation around
the dispatch boundary, expiry after readiness and restart recovery. Composed
approval/DPoP preflight pins the successful grant: its retained grant sequence
is `[0, 1, 1]`, not a fresh retry of the rejected grant after issuance.

The DPoP preview helpers now have a focused module. This keeps `dispatch.rs`
below its existing 2,000-line gate without increasing an allowance. Six new
formal source anchors cover DPoP acquisition, exact cleanup and permission
preview; existing anchors now include the consuming multi-credential helper
and shared rollback implementation. Review refreshed fourteen of ninety-five
mirror entries. No model transition, assumption or bound changed; these source
anchors do not prove SQL atomicity, expiry or process-loss recovery.

Final serial qualification with Rust 1.94.1, offline dependencies,
`CARGO_INCREMENTAL=0`, `/tmp/chio-security-target.rHKDaO`, `umask 022` and two
test threads passed 1,314 kernel library tests, 13 direct DPoP tests, six
admission-equivalence tests, 11 kernel/SQLite integration tests, four formal
projection tests, 1,407 SQLite library tests, 21 caller-execution tests, 15
execution-nonce lifecycle tests, one governed-approval replay test and 58 remote
MCP library tests. That is 2,850 passing selected Rust tests. The full SQLite
library run completed in 906.88 seconds. The kernel library rerun after the
test-helper formatting pass again passed all 1,314 tests.

Four pre-existing ignores remain: the intentionally unimplemented external
lost-report handshake contract, the SQLite serving-owner child helper, the scale
proof and the known wedged-retention case. None is counted as passing evidence;
subprocess helper output is not counted as another top-level test. All 22
formal-mirror regressions pass, including a new coverage-fixture regression.
The fixture now unions required symbols for each model/source pair, so
overlapping coverage groups produce one complete manifest entry. The production
coverage gate still rejects each independently omitted required symbol.

Strict all-target Clippy passed for `chio-kernel`, `chio-store-sqlite`,
`chio-mcp-remote`, `chio-api-protect`, `chio-conformance`, `chio-acp-edge`,
`chio-cli`, `chio-finding-hosted-edge`, `chio-control-plane` and `xtask`.
The final kernel all-target Clippy rerun and kernel no-default-features check
also passed. No warning gate or allowance was relaxed. Workspace and explicitly
included-test formatting, diff whitespace, Rust file hygiene, public-surface
policy, formal mapping, the Apalache slice static contract and security CI
static contract passed, together with mapping, hygiene, public-surface and
security-CI mutation self-tests. All 95 formal mirrors match; regenerated proof
coverage matches 58 rows and 168 artifacts. The final code graph has 162,252
nodes, 422,241 edges and 6,958 communities. These are consistency checks, not
new theorem or model-checker qualification. Proof wire/signing and SDK sources
are unchanged in this slice; SDK runtime tests were not rerun.

No user source was activated and no commit, push, hosted CI rerun, workflow
repin, merge or publication was performed. WIP classification covers 430
individual files across 11 slices with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`, and the existing Cargo.lock is
unchanged during this slice. The checkpoint remains uncommitted in the isolated
launch worktree. Full-workspace, exact-candidate hosted, native platform and
release qualification remain open.

Complete caller credential/security-hook custody, authenticated external start,
independent executor claims and authenticated delivery reports remain open.
Complete combined runtime/credential interruption and independent-process
qualification, SDK/client migration, the original roadmap gates, native platform
evidence, dependency audits, observed pilot and release qualification also remain
open. This milestone does not close the full goal or authorize launch.

The next implementation boundary is the complete typed caller admission
snapshot, joining the qualified runtime, approval and DPoP ownership references
with supported security-hook custody. Qualification must include composed
reserve-for-caller/preflight behavior and reject unsupported participants before
granting external authority. The retained return-context component is not that
snapshot and cannot substitute for the dispatch-start handshake.

### Live security-owner containment and caller profile rejection

Tracing the next caller snapshot boundary found two live-hook defects and an
unsupported caller composition. Before the fix, acquisition and commit panics
escaped evaluation, and a hook could return an outcome owner naming another
request or commitment while the kernel still dispatched and returned Allow.
A physical SQLite regression also reproduced a composed approval/DPoP caller
reservation returning Allow even though the report path reconstructs a
secret-free request and cannot recover those credentials.

The kernel now validates the outcome owner's request and canonical commitment
before connector entry. A shared security-owner module contains acquisition,
commit, outcome recording, disposal and final-release callbacks. Recording and
recorder disposal unwind separately, including when cleanup runs during another
unwind. Request lifecycle disposal is contained on early return. Rejection
logging no longer calls extension-provided `name()` code. Post-effect callback
errors and panics use a non-retryable, non-redispatchable recovery error without
copying callback details into the response. Ordinary and nested execution share
the same checked final-release response helper. These are live Rust owners, not
persisted security authority; native aborts and arbitrary trusted extension code
are outside unwind containment.

The existing two-call caller reservation API now rejects presented DPoP,
approval sets/tokens, threshold proposals, supplemental authorization and
declassification artifacts, DPoP-required matching grants, and configured
security-hook/enforcement profiles before admission mutation. It does not mint
a nonce or acquire quota or credential episodes for those unsupported profiles.
An already-issued nonce and its original composed history remain unchanged by
rejection and remain usable by ordinary kernel dispatch. This is an explicit
fail-closed restriction until durable snapshot/start/report support exists, not
replacement of that requirement. The separate legacy reserving-preflight route
already rejects durable nonce composition; its approval phase guard was not
relaxed or bypassed.

Fifteen new behavioral regressions pass in focused qualification: eleven public
security-adapter cases, two kernel nested/logging cases and two physical SQLite
caller cases. The complete adapter suite passes 34 tests and the configured
SQLite DPoP route group passes 14. All 22 mirror-checker tests pass. Three new
required source anchors cover the live-owner module, security hook and caller
profile guard; seven reviewed mirror entries were refreshed and all 98 match.
No model transition, assumption or resource bound changed. These hashes record
implementation review, not a theorem about extension panics or security-store
atomicity. Structural and mutation checks for file hygiene, public surfaces,
formal mapping and security CI pass; the Apalache slice static contract passes.
No size allowance or warning gate was relaxed.

Broader qualification passed all 987 control-plane and 1,316 kernel library
tests. SQLite then exposed an intermittent `SQLITE_BUSY` in its existing
migration-opener fixture; the same case reproduced in isolation on the seventh
attempt. The fixture dropped a pooled source and assumed it could immediately
change journal modes. Setup now waits with a deadline for the exact requested
mode, retrying only `SQLITE_BUSY`. It never retries the migration opener or its
policy assertions. Two additional fixture regressions cover transient teardown
and a permanently busy source. All eight integrity tests and 50 consecutive
isolated opener checks pass. The original migration refusal assertions remain.

Final serial qualification passes. SQLite was rebuilt with the same feature
combination as the failed broad run and passes 1,411 library tests with three
existing ignores. The selected SQLite caller, nonce-lifecycle and governed
approval integrations pass 21, 15 and one test respectively, with the existing
lost-report ignore unchanged. Kernel DPoP, admission equivalence, durable SQLite
admission and formal projection integrations pass 13, six, 11 and four tests;
the remote MCP library passes all 58. Together with the control-plane, kernel
and security-adapter suites above, this is 3,877 distinct passing Rust cases
and four existing ignores, plus 22 mirror-checker tests. Seventeen new tests
cover the fifteen security behaviors and two fixture contracts. Focused repeats,
the 50-run fixture stress check and helper-process executions are not additional
distinct cases. No new test is ignored.

Strict all-target Clippy passes for the eleven selected kernel, store, security,
control-plane, remote MCP, API-protect, conformance, ACP-edge, CLI, hosted-finding
edge and xtask packages. Kernel no-default-feature checking, formatting and
diff whitespace checks pass. Proof coverage is regenerated and checked at 58
rows and 168 artifacts; all 98 formal mirrors match. These checks use Rust
1.94.1 offline, `umask 022`, disabled incremental compilation and serial Cargo
commands against the isolated target directory. The final code graph refresh
completed with 162,363 nodes, 422,509 edges and 7,037 communities. The accumulated
worktree contains 436 changed or untracked files across eleven review slices,
with none unclassified. This is bounded local qualification, not a full-workspace
run or exact-candidate hosted qualification.

The full caller snapshot and operation-owned security participants remain open.
In particular, final-release failure followed by terminal replay and restart
must be tested against a persisted security-release authority. The immediate
response gate is not that checkpoint. Authenticated external start, independent
executor claims and reports, the existing ignored lost-report contract, combined
interruption/process-crash matrices, SDK/client migration and the entire
original platform/audit/pilot/release scope remain required. No user source was
activated, and no commit, push, hosted rerun, workflow repin, merge or publication
was performed. Work remains isolated and uncommitted; HEAD and the existing
Cargo.lock are unchanged during this slice.

### Durable final-release checkpoint and replay containment

Two physical SQLite counterexamples reproduced the remaining release gap: a
live final-release failure withheld the first response, but an identical retry
and a restart replay both returned the already-completed Allow receipt and
output. The failure occurred after terminal projection, leaving no durable
release requirement for either recovery path to enforce.

Ordinary and nested durable dispatch now freeze whether an original live
security lifecycle owner exists before committing dispatch. An unsupported
checkpoint backend rejects before the effect boundary. A new canonical raw
outcome schema preserves that exact requirement and the original request and
security context. Legacy security-context payloads without a qualified
requirement remain readable as historical data but cannot infer release
eligibility. Federation context cannot overwrite the new schema or requirement.

After output evaluation and monetary settlement, the original live owner must
acknowledge the exact dispatch commitment. Only that kernel path constructs an
opaque, non-cloneable and non-serializable acknowledgement. SQLite records it in
a separate immutable checkpoint table under the exact current operation recovery
lease and serving fence. The record binds the original request, operation,
dispatch commitment, raw outcome, resolved evaluation and output, and is committed
into the existing anchored admission participant journal. The acknowledgement
time is selected after the callback; terminal evidence uses a refreshed decision
time. The kernel requires exact persisted readback before terminal projection.
Release is neither a pure output-evaluation step nor monetary settlement proof.

Completed replay independently requires this checkpoint. Pending recovery cannot
consume a fresh lifecycle owner, rerun the tool or publish output without the
original acknowledgement. A missing owner or a failed checkpoint write retains
Finalizing and captured quota; unresolved startup withholds serving readiness.
A checkpoint committed before a lost acknowledgement can recover its exact
historical release without a second callback or effect. This closes the observed
bypass but deliberately does not recover a lost native owner.

The outcome schema advances from version 2 to 3. Migration accepts exact
historical v1, v2 and unversioned predecessor catalogs without inventing release
records. It refuses release artifacts under an older version, unqualified
release tables/views, missing predecessor guards, and a cleared application
identity containing release state or version metadata. Identity validation,
stamping, schema migration and final invariant checks share one immediate
transaction, so a failed source check cannot repair or restamp the source.
An exact unstamped legacy source is stamped only after successful migration.
Alternate-case or non-table version metadata cannot hide a source revision from
the shared schema helper. Existing immutable payload-retention rules remain.

Focused qualification passes eighteen physical release tests and sixteen
outcome-store tests, including nine migration contracts. Three real subprocess
aborts exercise resolved output before release, live acknowledgement before its
checkpoint, and a committed checkpoint before terminal projection. Integrity
tests reject omission, changed bindings, and a rewritten record with a recomputed
local digest, using the independent admission journal commitment. Fault tests
exercise unsupported stores, pre-commit failure and lost write acknowledgement.
Additional cases exercise the public nested session route, retained checkpoint
verification after payload compaction and owner rotation, and acknowledgement
time after the native callback. Four additional physical payment/security
composition cases cover capture and contractual zero-charge settlement followed
by successful or refused security release, retry and restart. Settlement always
precedes the security callback, and neither settlement nor the tool effect is
repeated. All 1,317 kernel library tests pass, including the new real-federation
codec-order regression and expanded legacy requirement checks. All 987
control-plane tests also pass. The superseded partial SQLite
library run was interrupted for the final namespace check and is not counted as
a pass. The final common-feature binary passed all 1,420 SQLite library tests,
with three existing ignores, and all 52 security-kernel integration tests pass.
The selected SQLite integrations pass 66 cases, including the eighteen release
cases, with one existing caller lost-report ignore. Kernel DPoP, equivalence,
durable SQLite and formal-projection integrations pass 38 cases, including the
four payment/security cases. The MCP remote library passes 58 cases. Together,
these selected behavioral suites pass 3,938 distinct cases with four existing
ignores. The final kernel, SQLite and control-plane library binaries were built
together with the same feature selection and tested from their package roots.
There are 32 new regression cases in this slice; focused repeats and helper
processes are not additional distinct tests. No new test is ignored.

All 22 mirror-checker tests pass. All 105 formal source anchors match after
review and regeneration, including the expanded codec and store-port anchors
and final namespace guard. Regenerated proof coverage matches 58 rows and 168
artifacts. No model transition, assumption or resource bound was changed. Strict
all-target Clippy passes with warnings denied for the kernel, SQLite store,
security kernel, control plane, MCP remote, API protect, conformance, ACP edge,
CLI, hosted finding edge and xtask packages. The kernel no-default-features
build, formatting, diff whitespace, Rust hygiene, public-surface, security-CI,
Apalache slice and formal-mapping static gates pass, including the applicable
mutation self-tests. These checks use Rust 1.94.1 offline, locked dependencies,
`umask 022`, disabled incremental compilation and serial Cargo commands against
the isolated target directory. This is bounded local qualification, not a
full-workspace run or exact-candidate hosted qualification.

The final code graph refresh completed with 162,564 nodes, 423,046 edges and
6,972 communities. The accumulated worktree contains 450 changed or untracked
files across eleven review slices, with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`; the existing Cargo.lock SHA-256 remains
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

Recoverable operation-owned flow/declassification/security participant custody,
the full caller snapshot, current release-policy revalidation, authenticated
external start and delivery reports remain open. So do the ignored lost-report
contract, complete composed interruption and independent-process matrices,
SDK/client migration and every original platform, audit, pilot and release gate.
Historical release evidence is not fresh invocation authority. No user source
was activated, and no commit, push, hosted rerun, workflow repin, merge or
publication was performed. Work remains isolated and uncommitted. This
checkpoint does not close the entire roadmap or qualify a launch.

### Prepared production flow dispatch and fresh consumption

The production flow resolver now separates a non-consuming validated plan from
the mutation that commits flow and declassification. `PreparedFlowDispatch` is
one-shot, non-cloneable, non-serializable and bound to its originating resolver.
It retains the original classification, verified grant, flow snapshot, manifest
and policy selection, request identity and dispatch commitment. Preparation and
Drop perform no declassification consumption, flow join, fence acquisition or
receipt append. The existing production dispatch entry consumes this same plan.

Commit accepts no replacement input or backend. It validates the exact current
flow snapshot and takes a fresh authority clock observation after read-only
evidence callbacks. Changed state, clock rollback, expired grants and expired
original fence plans reject before participant writes; preparation does not
renew a permission. Consumption records the fresh timestamp rather than the
earlier preparation time. Exact prior consumption denies replay without another
consume attempt. Existing attested outcome and sink-readback behavior remains.
The implementation is extracted into a focused Rust module instead of extending
the already large adapter include.

Thirteen new regression cases cover the engine's fresh-time and required-grant
rules and the production resolver with physical SQLite flow and declassification
state. They include dropped preparation, fresh consumption timestamps, unchanged
classification, ordinary fences, expiry, clock rollback, competing flow state,
overlapping preparations, a two-thread commit race, and expiry during an evidence
lookup. A compile-fail documentation example checks the one-shot commit API.
The existing failure-time tests now also assert the actual persisted consumption
timestamp. A temporary negative control moved validation before the evidence
lookup. The exact delayed-expiry test then failed because SQLite acquired
restricted flow labels and advanced its generation after expiry. The corrected
ordering was restored before broader qualification. This is an executed
ordering counterexample, not an external tool-execution or process-loss claim.

Final local qualification passes all 44 flow-engine library tests, 997
control-plane library tests, 52 security-kernel integration tests and 43 SQLite
security-state/contract tests: 1,136 distinct behavioral cases, with no ignores
in these selected suites. Focused repeats are not additional cases. The one-shot
API compile-fail example passes separately. Existing ignored roadmap contracts
were neither enabled nor weakened. Strict all-target Clippy passes with warnings
denied for flow, control-plane, security-kernel, SQLite and xtask; the flow crate
also passes its no-default-features build. All 22 mirror-checker tests pass, all
107 source anchors match after review and regeneration, and proof coverage
matches 58 rows and 168 artifacts. No model transition, assumption or bound
changed. These source anchors are drift checks, not an atomicity proof.

Formatting, including the new included test sources, diff whitespace, Rust
hygiene, public-surface, security-CI, Apalache slice and mapping gates pass, as do
the applicable mutation self-tests. The final source-content fingerprints are
unchanged through qualification. Checks use Rust 1.94.1 offline with locked
dependencies, `umask 022`, disabled incremental compilation and serial Cargo
commands in the isolated target directory. The graph refresh completed with
162,643 nodes, 423,281 edges and 6,958 communities. The accumulated worktree has
458 changed or untracked files across eleven review slices, none unclassified.
HEAD and the existing Cargo.lock are unchanged during this slice. This is bounded
local qualification, not a full-workspace run or exact-candidate hosted result.

This is a prerequisite for the full caller snapshot, not operation-owned security
custody or an external execution permit. The flow, declassification and receipt
stores still use separate transactions, with their existing fences and replay
checks for later races. Durable owner references, legacy-source retirement,
joined admission authority, recovery, current release policy and authenticated
start/report remain open, along with every original platform/audit/pilot/release
gate. No source activation, commit, push, hosted rerun, workflow repin, merge or
publication was performed. The entire roadmap remains active.

### Exact flow and declassification source retirement

The legacy security store now has an explicit migration-only retirement boundary,
`security_state::SqliteSecurityParticipantSource`. Opening observes an existing
regular, single-link SQLite main file without creation, migration, pruning or
schema stamping. Exact catalog and application/schema identity, WAL with
synchronous FULL, bounded physical inventory and existing flow/declassification
integrity checks are required. The source is bound to SQLite's actual descriptor
using the audited file-identity utility, not merely to pathname metadata.

An independently retained preview fingerprints all fourteen critical tables,
including monotonic flow state, isolation/session membership, generation
high-water, historical egress fences, pending and terminal declassification
evidence, receipt outbox state, compacted replay tombstones and shared transitions.
Typed, length-framed canonical row digests bind complete retained rows without
putting those rows into the fingerprint. Limits are 16,384 rows, 64 MiB of encoded
inventory, 1 MiB per cell, 2 MiB per raw row and a 64 KiB canonical fingerprint.
Source/authority/destination labels bind the expectation but do not establish a
destination's real authority. The fingerprint is not an importable inventory.

`seal_exact` compares the complete source before its first write in one immediate
transaction, installs immutable seal evidence and 48 persistent write barriers,
then requires exact readback. Existing typed security-store handles and the
ordinary opener refuse service after retirement. Older SQL connections cannot
insert, update, delete, replace or ignore-conflict their way past the critical
table or version barriers. This seal must not be confused with the older
`live_dispatch_sealed` flag, which enables live declassification dispatch.

Eighteen new behavioral cases and one child-process test helper cover populated
flow/declassification history, all barriers with recursive triggers disabled,
stale expectations, competing flow joins, malformed or substituted catalog/seal/
row/file evidence, bounds and durability settings, rollback, exact retry and
reopen. An independently computed v1 table-digest vector guards against
incompatible fingerprint encoding drift that roundtrips alone would miss.
The real child-process matrix aborts after DDL, seal insertion, barrier
installation, pre-commit verification and commit. The first four cases reopen
unsealed and unchanged; the fifth recovers the exact committed seal without
resuming legacy writers. These are process-crash observations, not power-loss
or hostile-filesystem qualification. Existing ignored contracts are unchanged.

Local qualification passes 1,439 SQLite library tests, 43 security-state
integration/contract tests, 997 control-plane library tests, 52 security-kernel
integration tests and 44 flow-engine tests: 2,575 reported test passes across
these suites, without counting focused repeats or nested child invocations
again. Three existing SQLite library annotations remain ignored in the parent
run: the retention state-machine property (reported CI wedge), the separate
million-receipt release-mode scale proof, and the serving-owner subprocess
helper. These are not counted as passes. All nineteen retirement test entries
were rerun with the fixed vector; eighteen are behavioral cases and one is the
child-process helper. The production source remained unchanged through the
broader run; the strengthened codec regression was independently rerun afterward.

Strict all-target Clippy passes with warnings denied for SQLite, control-plane,
security-kernel, flow and xtask. All 22 mirror-checker tests pass and all 107
existing source anchors match. Coverage regeneration corrected the input digest
made stale by the mapping documentation change; the final check matches 58 rows
and 168 artifacts. No model transition, assumption or bound changed, and the
source-retirement SQL boundary is not claimed as a modeled atomicity proof.
Formatting, whitespace, Rust hygiene, public-surface, security-CI, Apalache-slice
and mapping checks pass, including the applicable mutation self-tests. Final
targeted tests and metadata checks use Rust 1.94.1, locked/offline dependencies,
`umask 022`, disabled incremental compilation and serial Cargo execution.

The final code graph has 162,760 nodes, 423,575 edges and 7,029 communities. The
accumulated worktree contains 470 changed or untracked files across eleven review
slices, with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`, and the existing Cargo.lock SHA-256
remains `869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
This is bounded local qualification, not a full-workspace run, exact-candidate
hosted qualification or a launch-ready claim.

This is source retirement only and remains unsuitable for activating a serving
destination. Operators must quiesce the whole old security service; unrelated
active-defense tables are not claimed frozen or transferred, and already
admitted in-memory work cannot be retracted. Destination expected-pin, actual
row transfer/import, inactive validation, activation and all affected consumers
still need implementation and qualification. So do operation-fenced security
claim/release/commit/recovery, the full caller admission snapshot, current release
policy, authenticated external start/report, the ignored lost-report contract,
complete composed process/interruption matrices, SDK/client migration, native
platform evidence, dependency audits, observed pilot and release gates. No source
activation, commit, push, hosted rerun, workflow repin, merge or publication was
performed. Work remains isolated and uncommitted; the entire roadmap is active.

### Exact source pin and complete inactive security inventory

Admission schema v27 adds destination-side pinning and complete inactive import
to the source-retirement boundary above. The real destination serving fence and
physical file identity are checked independently. A deterministic expectation
retains the complete source fingerprint before sealing; source I/O is outside
destination locks. The importer reads a live verified seal and copies every
canonical critical-table row, including pending uses, terminal evidence, outbox
records and compacted replay tombstones. No original source row is pruned or
converted into a newly granted permission.

The destination transaction commits immutable retained rows, a chained local
import event and its global authority reference together, then synchronizes the
independent rollback anchor and performs exact readback. Every read verifies
actual row hashes, counts, contiguous indexes, historical fences and global
coverage. Nine persistent triggers prohibit mutation, replacement and additions
to a completed archive. Exact predecessor upgrades add empty tables without
adopting partial/future namespaces or changing old event digests. Pending pins
reserve their complete inventories against sixteen-source, 65,536-row and 64 MiB
destination limits before any source is retired.

Nineteen added test entries comprise eighteen behavioral regressions and one
subprocess helper. They cover complete retained row bytes, pending/terminal/
compacted declassification history, stale pins, conflicting identities,
independent source/destination file identity, exact retries, competing imports,
source loss, tampered local/global history, immutable triggers and exact schema
upgrades. Clock tests require the independently observed authority time, even
when a plausible caller timestamp could otherwise conceal rollback. Capacity
tests cover exact aggregate limits, excess and checked-arithmetic overflow.
Eight ordinary-error cutpoints verify transaction rollback and lost-ack retry;
ten real process-abort cutpoints also cover the SQLite-commit/independent-anchor
gap. A stale private destination restore is rejected against the retained
independent anchor. These are process and private-file observations, not a
power-loss or hostile-filesystem qualification.

Global reference lookup verifies the referenced source's actual retained rows,
while the coverage pass verifies every source, reserved capacity and exact
global linkage. It does not rehash every source for each individual reference.
Only the compiled canonical schema definition is cached; live catalog checks
and row verification are not cached by this migration module. This avoids a
quadratic inventory rescan without claiming a qualified latency profile.

Final local qualification passes 1,458 SQLite library tests, 61 security-state/
contract/release-recovery integration tests, 997 control-plane library tests,
52 security-kernel integration tests and 44 flow-engine tests: 2,612 reported
Rust test passes, excluding focused repeats and nested child invocations.
The three existing SQLite ignored annotations remain unchanged: the retention
state-machine property, separate release-mode million-receipt scale campaign
and serving-owner subprocess helper. They are not counted as passes. Strict
all-target Clippy passes for SQLite, control-plane, security-kernel, flow and
xtask. All 22 mirror-checker tests pass, all 107 existing anchors match, and
regenerated coverage matches 58 rows and 168 artifacts. No abstract model
transition, assumption or bound changed; the inactive transfer is not claimed
as a modeled atomicity or ownership proof.

Formatting, whitespace, Rust hygiene, public-surface, security-CI, Apalache-slice
and mapping checks pass, along with their applicable mutation self-tests.
Qualification uses Rust 1.94.1, locked/offline dependencies, `umask 022`, disabled
incremental compilation and serial Cargo/test execution. The refreshed code
graph contains 162,892 nodes, 423,875 edges and 6,946 communities. The accumulated
worktree contains 481 changed or untracked files across eleven review slices,
with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`; the existing Cargo.lock SHA-256 remains
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
This is bounded local qualification, not a full-workspace run, an exact-candidate
hosted result or a launch-ready claim.

This checkpoint has only `Expected` and `ImportedInactive` phases. It does not
hydrate a serving flow store, activate a security authority, recover a live
admission owner, resume a pending dispatch or authorize an external effect.
Activation, real operation-fenced flow/declassification/security custody and
recovery, every affected legacy consumer, the full caller snapshot and current
release policy remain open. All other roadmap work remains in scope, including
authenticated external start/report, the ignored lost-report contract, complete
composed process/interruption matrices, SDK/client migration, native platform
qualification, dependency audits, observed pilot and release gates. No operator
database, commit, push, hosted rerun, workflow repin, merge or publication is part
of this implementation. Work remains isolated and uncommitted.

### Security-state deadlines after database contention

Review of the flow and declassification activation prerequisites exposed stale
trusted-clock reads in the existing security store. Thirty operations sampled
time before acquiring the connection mutex or SQLite lock. A real lock wait
could consume a fence or scheduler lease's remaining lifetime while the resumed
operation still accepted the earlier timestamp.

All thirty reads now occur inside the security-state transaction. The private
clock boundary requires a transaction and performs the retirement-state read
before sampling time, establishing a SQLite snapshot even for deferred reads.
The three already-transactional clock sites use the same boundary. Egress and
scheduler validators now keep their related SQL reads in one deferred snapshot.
This covers flow fences, lineage-fence lifecycle, scheduler claims and recovery,
effect persistence, containment, throttles, capability suspension, issuance
freezes and egress restrictions. It does not turn a point-in-time check into a
permit for a later external effect.

Seven negative regressions reproduced expired-authority acceptance before the
fix while the still-live control passed. Twenty-two deterministic tests now
exercise actual SQLite lock contention, boundary equality, valid controls,
failed mutations leaving durable state unchanged, clock unavailability and
deferred snapshot acquisition. Mutations use the production WAL profile; read
contention uses a private rollback-journal fixture. Exact replay of an already
committed egress decision remains evidence and succeeds after expiry or clock
failure, while a different commitment still conflicts. No production fault hook,
sleep-based race, schema migration or new public authority type was introduced.

Local qualification passes 41 security-state library tests, 111 affected SQLite
integration tests, 19 destination-import tests, 234 selected control-plane
tests, 52 security-kernel integration tests and 44 flow tests: 501 reported
passes, excluding focused repeats and nested child invocations. Strict
all-target Clippy passes for SQLite, control-plane, security-kernel, flow and
xtask. Formatting and whitespace checks pass; all 107 existing formal anchors
match, and regenerated proof coverage matches 58 rows and 168 artifacts. No
abstract model transition, assumption or bound changed. The code graph was
refreshed to 162,947 nodes, 424,026 edges and 7,003 communities.

Qualification uses Rust 1.94.1, locked/offline dependencies, `umask 022`, disabled
incremental compilation and serial Cargo/test execution. The accumulated
worktree has 494 changed or untracked files in eleven review slices, with none
unclassified. HEAD and the existing Cargo.lock hash remain those recorded in
the inactive-import checkpoint above. This is affected-suite qualification,
not a fresh full-workspace run, exact-head hosted result or new formal proof.

This is not launch qualification. The inactive-import checkpoint remains inactive:
operation-fenced mutable custody and recovery, activation, all affected legacy
consumers, the complete caller snapshot and current release policy remain open.
Every other roadmap and release gate remains in scope. Work remains isolated
and uncommitted; no operator database or external release state is changed.

### Transaction-owned flow and declassification engine

The legacy store now delegates flow joins, isolation-epoch mutation, egress-fence
acquisition/commit and declassification consumption/outcome evidence to one
internal transaction-owned engine. The owner accepts only an already-acquired
main-database write transaction, overrides commit-on-drop with rollback, and is
returned only when a mutation succeeds. No engine method commits independently.
This lets a coordinator compose the real flow/use/outbox mutations and other
participant writes under one outer commit. An error or dropped owner rolls back
the entire uncommitted transaction, not just the last SQL statement. This is not
permission to reverse committed taint or replay history during compensation.

The original public store methods remain adapters that perform their own outer
commit. Flow snapshot reads now use one deferred snapshot. Flow SQL is organized
into label, generation, epoch, join and fence modules rather than embedded in
the numbered declassification implementation. The source-retirement inventory
uses the same snapshot decoder as the live store.

Isolation-evidence verification runs outside the connection and write lock.
The port verifies durable isolation/destruction evidence bound to the complete
transition, not transient permission. The store rechecks replay, prior/new epoch
state and current lineage after verification. Tests exercise a concurrent lineage
join, an identical transition, a conflicting transition and source retirement
during the callback. Exact committed replay avoids invoking the verifier again.

Fresh declassification had a separate deadline gap: it trusted the receipt's
consumption timestamp without independently sampling the store clock. Two real
SQLite-wait regressions reproduced acceptance after expiry and clock failure.
Fresh consumption now checks independently observed time after acquiring the
write transaction, with strict expiry and the existing clock-skew bound. Exact
retained use/evidence replay remains historical evidence and does not require a
fresh clock. Test-only history and conformance fixtures now explicitly configure
their intended trusted clocks; production clock checks are not bypassed.

Native tests exercise joint flow/use/outbox visibility, late statement failure,
drop cancellation, preexisting taint preservation, caller commit-on-drop and
rejection of unacquired/read-only transactions. Seventeen new tests cover the
owned transaction, verifier races and fresh declassification deadline behavior.
The serial affected-suite run reports 528 passing tests: 58 security-state
library tests, 111 SQLite integrations, 19 participant-migration test entries,
234 selected control-plane security tests, 52 security-kernel integrations,
44 flow tests and ten active-defense conformance tests. Focused repeats and
nested child invocations are not added again. The security-types port contract
also compiles; its zero runtime tests are not behavioral evidence. Existing
full-suite ignored tests were not changed or counted as passing.

Strict all-target Clippy passes for the store, control plane, security kernel,
flow, conformance, security types and xtask. Formatting, whitespace, Rust hygiene,
public-surface, security-CI, Apalache-slice and mapping checks pass. All 107 formal
mirrors match; regenerated proof coverage matches 58 rows and 168 artifacts. No
abstract transition, assumption or bound changed, and these native tests do not
establish a new formal proof. The refreshed code graph has 163,046 nodes,
424,244 edges and 6,940 communities.

Qualification uses Rust 1.94.1, locked/offline dependencies, `umask 022`, disabled
incremental compilation and serial Cargo/test execution. The accumulated
worktree has 509 changed or untracked files in eleven review slices, with none
unclassified. HEAD and the existing Cargo.lock hash remain those recorded in
the inactive-import checkpoint. This is affected-suite qualification, not a
fresh full-workspace or exact-head hosted result. These changes do not add a
wire format, schema migration, admission-operation ownership proof or a serving
activation flag.

The engine currently operates on the legacy security tables. Native mutable
projection hydration, qualified activation, operation-fenced claim/release/commit
and recovery, every affected consumer, full caller snapshot and current release
policy remain required. Every other original roadmap, platform, audit, pilot and
release gate stays in scope. Work remains isolated and uncommitted; no real
operator database, hosted run, workflow pin or release state was changed.

### Retained security-row decoding and egress-history validation

Migration preparation exposed four native counterexamples: acquisition replay
and live fence validation accepted partial commitment records, exact committed
replay accepted a substituted fence ID, and source preview accepted malformed
fence history. The retained-fence decoder is now shared by acquisition,
validation, commitment replay and source inventory. It checks all identifiers,
the canonical request-derived fence ID, positive generation/deadline and the
paired commitment ID/time. A historical commitment timestamp cannot exceed its
fence deadline. Source inventory also rejects orphan or future-generation
fences, while retaining valid expired, stale and committed records unchanged.
Exact committed replay still does not consult fresh time or reauthorize a call.

The source-row v1 format now has a bounded, lossless SQLite-value decoder used
by destination insertion and actual-row readback. Integer strings retain the
full signed 64-bit range, including values outside JSON's exact-number range.
Blobs retain exact bytes; text and null remain distinct. Column count, declared
storage types and nullability come from the compiled canonical predecessor,
not an observed or supplied catalog. Noncanonical JSON/cells, duplicate fields,
unknown tables, integer aliases/overflow and cell/row bound violations reject.
Source inventory checks the same cell shape before encoding. Persisted schema,
row bytes, fingerprint framing and source identity remain unchanged.

The decoder is data for hydration, not source verification or live custody.
A native regression supplies matching fingerprints over malformed rows and
verifies that the destination row-storage boundary still rejects them. A separate
disposable-projection test restores all fourteen tables with production triggers
enabled and compares complete v1 fingerprints. It stages consumption, retained
terminal use and outcome in dependency order within one private transaction;
archive order alone is insufficient because the live outbox trigger binds each
insert to its corresponding use state. This does not rewind any committed
source, recreate a live owner or qualify an operator activation.

Eleven new regression/codec tests cover these boundaries. The serial affected
run reports 539 passing tests: 68 security-state library tests, 111 SQLite
integrations, 20 participant-migration test entries, 234 selected control-plane
security tests, 52 security-kernel integrations, 44 flow tests and ten
active-defense conformance tests. Focused repeats, zero-test targets and nested
child invocations are not added again. Existing ignored tests are unchanged.

Strict all-target Clippy passes for the store, control plane, security kernel,
flow, conformance, security types and xtask. Formatting, whitespace, Rust hygiene,
public-surface, security-CI, Apalache-slice and mapping checks pass. All 107 formal
mirrors match, and regenerated proof coverage matches 58 rows and 168 artifacts.
No abstract transition, assumption, bound or formal proof claim changes. The
final code graph contains 163,103 nodes, 424,355 edges and 6,964 communities.

Qualification uses Rust 1.94.1, locked/offline dependencies, `umask 022`, disabled
incremental compilation and serial Cargo/test execution. The accumulated
worktree has 515 changed or untracked files in eleven review slices, with none
unclassified. HEAD and the existing Cargo.lock hash remain those recorded in
the inactive-import checkpoint. This is local affected-suite evidence, not a
full-workspace run, exact-head hosted qualification or launch approval.

Native mutable authority-scoped projection, operation-bound
claim/release/commit/recovery, every affected legacy consumer, the full caller
snapshot and current release policy remain required. All other original
roadmap, platform, audit, pilot and release gates remain in scope. The work is
isolated and uncommitted; no real operator database, external run, workflow pin
or release state is changed.

### Authority-scoped native security-state hydration

Admission schema v28 now restores the imported security inventory into fourteen
native relational tables, separate from the immutable v27 archive. Every primary
key, uniqueness constraint and cross-table foreign key includes the security
authority. Different sources may retain identical tenant, principal, session,
grant, request, evidence and transition identifiers without collision or merging.
The source catalog, source v1 row encoding/fingerprint framing and archive phases
remain unchanged.

Hydration owns one immediate transaction under the current serving fence and
independent rollback anchor. It streams bounded, losslessly decoded archive rows,
stages pending uses and consumption evidence before retained terminal uses and
outcome evidence, then hashes the actual authority-scoped native columns back to
every source table fingerprint. Source files and committed archive history are
never modified or replayed as fresh commands. Initialized native rows retain
spent grants, permanent tombstones, acknowledged/unacknowledged outbox evidence,
isolation history, flow generations and unresolved egress fences.

The same transaction appends immutable initialization metadata and one global
commit. Metadata binds the exact imported generation, native catalog digest,
independently observed time and historical owner lease. Acknowledgement follows
SQLite commit, independent-anchor synchronization and exact fenced readback.
Forty-two native-row and three metadata barriers prevent mutations after
initialization, including conflict-ignore/replace with recursive triggers off.
Three authority-scoped dependency triggers additionally protect evidence/use,
outcome-predecessor and permanent spent-grant relationships during hydration.

Readback rechecks bounded metadata, canonical catalog, actual native fingerprints
and exact global-reference coverage; metadata hashes alone do not suffice. Exact
retry and new-owner readback preserve the same initialization, including when the
retired source device is unavailable. Current owner and independently observed
clock checks still apply. A v27 upgrade adds only empty native tables, preserves
existing import/global history and refuses partial, future or alternate-case
native namespaces. Missing current barriers reject without repair.

Sixteen new native test entries pass. They cover scoped identities/dependencies,
immutable barriers, wrong source generation/fence,
tampering with a restored canonical catalog, clock rollback, private-file restore,
concurrent retry, owner rotation, source loss, five returned-error cutpoints and
six independent-process abort cutpoints, including commit before anchor sync.

The complete SQLite library run reports 1,524 passing tests, zero failures and
three existing ignored entries. The ignored entries are the retention-property
test marked with issue #1045, the release-only million-receipt scale proof and
the separately invoked serving-owner process helper. They are unchanged and are
not counted as passing evidence. The existing ignored external caller lost-report
contract also remains unimplemented; it is outside this library test target.

The serial affected run additionally passes 111 selected SQLite integrations,
234 selected control-plane security tests, 52 security-kernel integrations,
44 flow tests and ten active-defense conformance tests: 1,975 reported passes
in total. Focused repeats, zero-test targets and nested child summaries are not
added again. Strict all-target Clippy passes for the store, control plane,
security kernel, flow, conformance, security types and xtask. All 107 formal
mirrors match; regenerated proof coverage matches 58 rows and 168 artifacts.
No abstract-model transition, assumption, bound or proof claim changes.

Qualification uses Rust 1.94.1, locked/offline dependencies, `umask 022`, disabled
incremental compilation and serial Cargo/test execution. Formatting, whitespace,
Rust hygiene, public-surface, security-CI, Apalache-slice and mapping checks pass.
The refreshed code graph has 163,209 nodes, 424,685 edges and 6,989 communities.
The accumulated worktree contains 527 changed/untracked files in eleven review
slices, with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`; the pre-existing Cargo.lock SHA-256
remains `869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
This is local library/affected-suite evidence, not full-workspace, exact-head
hosted, native-platform, operational or launch qualification.

This is physical hydration, not activation or a mutable security-owner API.
No native `FlowStateStore`, declassification writer, operation claim/release/
commit/recovery or external execution permit is exposed. The legacy transaction
engine still requires qualified authority-scoped mutable integration and every
affected consumer migration. Activation must preserve the v28 initialization
digests and validate the current mutable rows through qualified mutation history;
an active flag cannot bypass comparison with the initialized source inventory.
The complete caller snapshot, authenticated external
start/delivery, current output/release policy and all original roadmap, native
platform, dependency-audit, pilot and release gates remain open. No real operator
database, commit, push, hosted run, workflow pin, merge or publication is changed.

### Authority-scoped flow engine and generation integrity

The flow domain engine now uses thirty closed legacy/native query pairs for
monotone label joins, context generations, isolation epochs, transition replay
and egress fences. Native SQL includes the authority in every read, mutation,
conflict key, cohort update, generation fallback branch and isolation-history
source selection. The binder checks exact domain arity, dense numbered parameters
and read/write statement classification, with authority first in native bindings.
No runtime table-prefix replacement, tenant encoding, temporary view or raw-SQL
escape hatch is used.

Read-only native inspection cannot construct a mutation view. Production writes
still borrow the legacy affine transaction owner, preserving whole-transaction
rollback on failure or cancellation, post-lock independent time sampling and
clock-independent exact committed-fence replay. The transition replay predicate
is shared with the other legacy security operations. Hydration exercises scoped
flow readers once after exact fingerprint validation. Subsequent inactive
readback retains the existing byte-exact checks, without repeatedly decoding
shared labels per retained context on every owner check. No v28 schema, catalog,
initialization digest or archive representation is changed.

Final review additionally found that live flow readers accepted generation zero,
although all valid stored flow labels and contexts have positive generations.
Principal, lineage, session and context reads now reject nonpositive generations
as integrity failures in both scopes. This prevents corrupt zero-generation
history from becoming an accepted snapshot or a fresh egress fence.

Thirteen new regression entries cover binding shape and read/write rejection,
colliding identities, every generation fallback branch, all three invalidation
cohorts, isolation evidence copying, independent fence commitments and historical
replay, missing-native-schema refusal, missing scoped dependencies, unchanged
initialized write barriers, nonpositive generation corruption and exact retained
cell parity across all nine flow/history tables. Native mutation construction is
test-only. Those fixtures use the actual v28 catalog and imported source parents,
roll back every speculative mutation and revalidate fenced initialization state.
They do not establish an operation owner or native serving permission.

The frozen Rust 1.94.1 locked/offline qualification run reports 565 passing test
entries: 81 security-state library tests, 33 admission security import/hydration
tests, 111 selected SQLite integrations, 234 selected control-plane tests,
52 security-kernel integration tests, 44 flow library tests and ten active-defense
conformance tests. The thirteen new entries are included in those counts.
Development repeats, subprocess summaries and the empty security-kernel library
wrapper are not counted again. The frozen-run log is
`/tmp/chio-security-scope-final.xBQKg5.log`.
This is affected-suite evidence, not a fresh full-SQLite-library or full-workspace
run, exact-head hosted qualification, native-platform qualification, operational
promotion or launch qualification. Existing unselected and ignored roadmap
requirements remain unqualified.

Strict all-target Clippy for the seven affected qualification packages, 107
formal-mirror checks, proof coverage generation/check (58 rows, 168 artifacts),
formatting, whitespace, Rust hygiene/public surface, security CI contract,
Apalache slice and mapping checks pass. These formal metadata checks do not
constitute new abstract-model proofs. The post-code AST graph is refreshed.
The worktree contains 538 changed or untracked files across eleven review slices,
with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`; the existing Cargo.lock SHA-256 remains
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

Declassification still needs authority-scoped mutation integration, including
lifecycle, use/evidence identity, outbox acknowledgement/retry and permanent
tombstones. Anchored current-state mutation history, actual admission-operation
claim/release/commit/recovery, destination activation and every affected legacy
consumer remain required. The complete caller snapshot, authenticated external
start/delivery, current output/release policy, all original roadmap requirements,
native-platform evidence, audits, pilot and release gates stay open. No real
operator database, commit, push, hosted run, workflow pin, merge or publication
is changed.

### Authority-scoped declassification engine and compaction integrity

Declassification now shares the checked SQL binder with flow through thirty-six
closed legacy/native query pairs. One domain implementation covers lifecycle,
one-shot consumption, terminal outcomes, evidence identity, pending and stranded
scans, acknowledgement, bounded retry and terminal compaction. Native authority
is bound first and appears in each lookup, mutation, join and correlated source
selection. The original thirty-five query pairs retain their SQL semantics;
the additional pair validates exact permanent evidence identity before compaction.
No runtime SQL rewriting, table alias fallback or native public store is added.

Legacy public mutations retain an outer rollback-owning transaction, including
reconciliation lifecycle and compaction. Consumption and outcome still compose
with flow through the affine owner. Errors and cancellation cannot commit a
partial use/outbox change through these production ports. Legacy readiness and
compaction candidate reads pin one deferred SQLite snapshot before querying
schema, lifecycle and evidence. Hydration additionally checks the scoped
declassification data after byte-exact retained-row comparison. Repeated inactive
readback and the v28 catalog, initialization and archive digests are unchanged.

Review found that direct compaction did not enforce the complete receipt-pair
binding checked at outcome creation and integrity inspection. Compaction now
uses the same grant/policy/request binding predicate, checks chronological order
and validates both permanent identity records before deleting live evidence.
A matching readiness cursor or individually canonical receipt cannot authorize
deletion of an inconsistent pair.

Fourteen new regression entries cover colliding authorities, exact historical
replay without a clock, fresh consumption and retry bounds, lifecycle/recovery,
ordered acknowledgement, tenant fairness, pending/stranded isolation, both
compaction pages, permanent spent grants, corrupt local identity joins and
canonical-but-mismatched grant hashes. They also compare every retained cell
across all five declassification tables, test native flow/use/outbox rollback,
legacy late-compaction rollback, absent-native-schema refusal, and initialized
mutation barriers. A deterministic two-connection WAL test commits compaction
between snapshot acquisition and domain inspection and verifies coherent old
rows throughout the reader transaction. Native mutations use the actual v28
catalog and imported parents in rollback-only test fixtures. Exact no-write
history/lifecycle results are not serving permission or activation.

The frozen Rust 1.94.1 locked/offline run reports 579 passing test entries:
95 security-state library tests, 33 admission security import/hydration tests,
111 selected SQLite integrations, 234 selected control-plane tests, 52
security-kernel integrations, 44 flow library tests and ten active-defense
conformance tests. The fourteen new entries are included. The twenty nonempty
test targets report zero failures and zero ignored tests. The empty
security-kernel library wrapper, development repeats and child-process summaries
are not additional coverage. The frozen-run log is
`/tmp/chio-security-declassification-final.hEa7tg.log`.
This is affected-suite evidence, not a fresh full-SQLite-library or workspace run,
hosted exact-head qualification, native-platform enforcement or launch approval.
Unselected and ignored roadmap requirements remain unqualified.

Strict all-target Clippy for the seven qualification packages, 107 formal-mirror
checks, proof coverage generation/check (58 rows, 168 artifacts), formatting,
whitespace, Rust hygiene/public surface, security CI, Apalache slice and mapping
checks pass. These metadata checks add no abstract-model proof. The refreshed
code graph has 163,406 nodes, 425,172 edges and 7,003 communities.
The worktree contains 559 changed/untracked files across eleven review slices,
with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`; Cargo.lock SHA-256 remains
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
All Cargo invocations and tests ran serially with `umask 022` and incremental
compilation disabled.

The next integration remains actual operation-fenced native mutation custody
and anchored current-state history rooted in the unchanged initialization, with
qualified claim/release/commit/recovery and explicit destination activation.
Every affected legacy consumer still needs migration, including security state
outside the fourteen archived tables. The full caller snapshot, authenticated
external start and delivery, current output/release policy and all original
protocol, active-defense and enterprise requirements remain open. Native
x86_64 platform evidence, dependency audits, pilot and release gates are not
closed by these local tests. No real operator database, commit, push, hosted run,
workflow pin, merge or publication is changed.

### Stable security identity before durable operation recovery

A reproducing regression showed that a completed durable request could return
its original successful output and receipt to a retry with a different trusted
security context generation. The original immutable request hash did not include
trusted security context, so recovery ran before the changed identity was checked.

The coordinator now binds tenant, session, principal, isolation epoch, lineage
root and context generation before original operation begin and exact replay.
Hook-presence and enforcement requirements are included. Stable identity comes
from the trusted host boundary, never agent request metadata. Both ordinary and
nested paths, pre-dispatch context freeze and private caller payload decoding
check this binding. A separately valid context cannot replace the admitted one.
Raw-return finalization reconstructs the historical binding without a new
invocation; approval collection uses retained data without promoting it to fresh
execution authority.

Security-bound operations use a versioned v2 request digest and, where original
retention is already required, a private v2 artifact with exact typed canonical
decoding. Truly unbound v1 hashes and bytes remain unchanged. Flow-state generation
is a mutable observation and may advance without changing operation identity.
The live participant must validate that observation at claim/dispatch. Large
ordinary requests acquire no new retention limit. Existing context-bearing v1
operations cannot silently acquire the missing v2 identity binding. Configuration
drift fails closed in recovered evaluation; hook presence is not a commitment to
the hook implementation or underlying security authority.

Fourteen new regression entries cover changed/added/removed identity, normal and
nested replay, requirement changes, pre-capture rejection, raw-return recovery,
caller payload substitution, strict codec rejection, v1 compatibility and large
requests. Real SQLite tests retain the exact security-bound original request
through nonce preflight and owner takeover, reject changed identity before nonce
reservation or new budget authorization, then execute and replay exactly once
with the original identity and an advanced flow observation. Ordinary completed
replay is also checked after owner takeover.

The evaluation entry wrapper and recorded terminal contract now live in focused
modules. Required drift coverage follows both the moved wrapper and its actual
implementation; the recorded-contract helper also has an explicit anchor. This
records reviewed implementation surfaces, not a new abstract-model guarantee.

The Rust 1.94.1 locked/offline behavioral run reports 2,138 passing test entries
across eleven nonempty targets: 1,329 kernel library tests; 69 tests across five
kernel integrations; 386 selected SQLite admission library tests; 21 caller and
17 nonce lifecycle integration tests; 82 runtime admission integration tests;
and 234 selected control-plane library tests. The fourteen new entries are
included. The caller suite also reports one deliberately ignored lost-report
and nonce-expiry counterexample requiring the missing external-start handshake.
That test is not passing evidence. Development repeats and nested process output
are not added to the count. The behavioral log is
`/tmp/chio-security-binding-final.LfwHLb.log`.
This is not a full SQLite library, workspace, hosted exact-head, native-platform
or launch qualification. Unselected and ignored roadmap work remains open.

Strict all-target Clippy passes for kernel, SQLite store, runtime core,
control plane and xtask. The behavioral/lint log ends with the expected
pre-refresh mirror drift. After reviewing the unchanged abstraction boundary,
nine of 110 anchor records were refreshed. All 110 now match, and twenty
drift-gate unit tests pass. Two empty filtered xtask integration wrappers add
no coverage. Proof coverage generation/check reports 58 rows and 168 artifacts.
Formatting, whitespace, Rust hygiene/public surface, security CI, Apalache slice
and mapping checks pass. The completed follow-up gate log is
`/tmp/chio-security-binding-gates.FkQ7DW.log`.

The final code graph contains 163,469 nodes, 425,333 edges and 6,993 communities.
The isolated worktree contains 566 changed/untracked files across eleven review
slices, with none unclassified. HEAD remains
`8b9f9243905dfa61acac82d83438684940777fe3`, and Cargo.lock SHA-256 remains
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
Cargo invocations and tests ran serially with `umask 022` and incremental
compilation disabled. No commit, push, hosted run, workflow pin, merge or
publication occurred.

This fixes a live prerequisite for native security ownership. Operation-fenced
native mutation custody, anchored mutable history rooted in initialization,
qualified claim/release/commit/recovery, explicit destination activation and
every affected legacy consumer remain open. The complete caller snapshot,
authenticated external start/delivery, current output/release policy, original
roadmap scope, native-platform evidence, audits, pilot and release gates remain
required. No real operator database or publication boundary is changed.

### Operation-owned native monotone join and anchored current rows

Admission schema v29 now includes the first actual native security mutation:
`join_security_participant_flow`. It checks the stored operation and its current
recovery lease in the owning immediate transaction, before budget capture or
dispatch. The original retained request must bind the trusted security identity,
enforcement requirement and installed hook. The host independently selects the
exact opaque initialization; agent metadata is not source-selection authority.
New joins require the current flow observation. One immutable join is permitted
per operation, and imported or other-owned transition IDs cannot be acquired.

Only that verified transaction can mint the private, affine join authorization.
The domain engine consumes it together with the owned transaction. Persistent
before-write barriers deny unowned writes, including ignored inserts. After-write
callbacks capture actual before/after row images, including shared principal and
session effects. Their authority is disabled and private temporary images are
released on success, error and unwinding. The callback admits only monotone flow
tables, not egress release or declassification consumption. Review also aligned
write admission with recovery: both reject row deletion, including nested
trigger effects, before incompatible history can commit. Capture and history
validation share one table vocabulary. The new nested-delete regression requires
the entire command to roll back without a journal or global-commit change.

The bounded canonical mutation record retains the original operation, historical
lease, trusted identity, exact command/result and lossless row changes. Native
rows verify against the unchanged imported inventory plus this ordered history.
Historical domain commands are not re-executed. The domain write, mutation record
and authority-wide commit share one SQL transaction and the existing rollback
anchor. Capacity exhaustion rolls back; history is never pruned to make room.
Exact retries and opaque fenced readback return historical observations, not new
execution authority. Monotone labels are not undone by later admission failure.

The v28 migration validates the complete predecessor before DDL, preserves its
original initialization bytes, catalog digest and global commits, and verifies
current v29 history independently. A genuine v28 initialization fixture now also
attempts a native join after migration. No operator database has been migrated.

Review reproduced an expired-lease acceptance when the caller clock was ahead
of the authority observation. The fix preserves both clocks: expiry uses their
maximum, each decision must follow its own operation's lease commit, and actual
authority observations impose global order. A later observation cannot hide a
regressed operation decision. An independent operation may have an earlier
decision timestamp. Expiry is rechecked immediately before enabling writes.
The original expiry regression and both distinct-clock causal ordering
regressions now pass. Restoring the former delete-admission behavior also made
the new nested-delete regression fail at its intended assertion: the join
committed history that recovery would reject. That negative-control log is
`/tmp/chio-native-delete-negative.n1r4ZT.log`. Fixed production files were
restored byte-for-byte afterward; the expected failure is not passing coverage.

The first broad behavioral run at
`/tmp/chio-native-join-final.FbbhRa.log` started before the latest clock/history
test edits. It was deliberately interrupted after 846 passing entries to
prioritize current-source qualification; it has no full-library result. Commands
queued after that test did not run. The current-source native/security-state
rerun at `/tmp/chio-native-current.Fc4G1N.log` passes 130 entries: 35 native
admission-state tests and 95 security-state tests, with zero failures or ignored
tests. Process-helper wrappers are not additional crash scenarios.
Tests include lease and owner substitution, shared-generation invalidation,
rollback and takeover, process
abort at five commit/anchor cutpoints, bounded capture exhaustion, expired
historical readback and canonical journal tampering with recomputed local
checksums. Unix process-signal tests are explicitly platform-gated.

The first broader current-source run at
`/tmp/chio-native-qualified.Sl1npc.log` passes 1,329 kernel library tests, 21
caller-execution tests and 17 nonce-lifecycle tests. The caller suite retains one
ignored lost-report/nonce-expiry counterexample requiring the unimplemented
external-start handshake. Two release-recovery assertions exposed fixture drift
from the earlier stable-security-binding change, not an output-release bypass.
Diagnostics observed an empty-output Deny for the changed profile and a startup
configuration-mismatch error before the release check.

The compaction fixture now preserves the original security profile so its retry
reaches the compacted-payload boundary. The hook-removal test checks the precise
configuration error, then restores a permissive hook under a new owner and
requires the same pending release to remain unresolved. Operation identity,
finalizing state, checkpoint absence, captured quota and single execution are
preserved; a fresh hook makes no release call. All 18 release-recovery tests pass
at `/tmp/chio-release-current.yzRhTQ.log`. The completed remaining checks and
fresh full SQLite library run are at `/tmp/chio-native-remaining.idTkUF.log`.

That remaining run has passed 15 kernel durable-admission integration tests,
82 runtime-admission tests and 234 selected control-plane tests. Strict
all-target Clippy passes for kernel, SQLite store, runtime core, control plane
and xtask. All 110 formal-mirror entries match without re-blessing, proof
coverage generation/check reports 58 rows and 168 artifacts, and 22 filtered
xtask tests pass (20 drift-module tests and two CLI parser tests). These are
drift and metadata checks, not a new abstract-model proof of native history.
The fresh full SQLite library run reports 1,570 passed, zero failed and three
ignored entries in 2,113.49 seconds. The ignored entries are the retention
state-machine property marked as wedging CI runners (issue #1045), the explicitly
release-mode million-receipt scale proof, and a serving-owner child-process
helper. The parent test invokes that helper separately; its nested one-test
summary is not additional coverage. The property and scale exclusions remain
unqualified. Together with the caller's ignored external-start counterexample,
the eight behavioral targets report 3,286 passing entries and four ignored
entries. The focused native/security-state repeats, fixed deletion control,
earlier partial run and negative control are not added to that total. This is
local affected-suite and full-SQLite-library evidence, not a fresh workspace,
hosted exact-head, native-platform, throughput or launch qualification.

Final formatting, whitespace, Rust hygiene/public surface, security-CI,
Apalache-slice and mapping checks pass. Their final static log is
`/tmp/chio-native-static-final.mhTt7k.log`; the corresponding static mutation
self-tests passed at `/tmp/chio-native-static.0GQtRJ.log`. The refreshed code
graph contains 163,594 nodes, 425,763 edges and 6,991 communities. The worktree
contains 579 changed/untracked files across eleven review slices, with none
unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`, and
Cargo.lock SHA-256 remains
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
The nonignored worktree file fingerprint, including hidden files but excluding
this mutable ledger and generated `docs/formal/COVERAGE.md`, remains
`2f5ac3240ab88ebc61ea7c89efff710ef230b347b76a65df5761148bddd61ef1`.
This local integrity check is not a signed release attestation. Cargo commands
and Rust tests ran serially with Rust 1.94.1, locked/offline dependencies,
`umask 022` and incremental compilation disabled.

The remaining native participant work includes immutable authority selection in
the complete original profile, dispatch-ledger attachment, egress and
declassification claim/release/commit/recovery, explicit destination activation
and every affected legacy consumer. The full caller snapshot and authenticated
start/delivery contract, current output/release policy, all original protocol,
active-defense and enterprise requirements, native platform evidence, audits,
pilot and release qualification remain open. This primitive neither selects a
live kernel adapter nor releases imported obligations. No commit, push, hosted
job, workflow pin, merge, publication or real operator activation has occurred.

### Original native authority selection at admission

The kernel now obtains a non-consuming native selection from trusted hook
configuration before begin. `NativeSecurityAuthorityBindingV1` is validated,
versioned data, not a mutation token: it binds destination UUID, security
authority identifier and the original initialization digest. It excludes current
serving ownership and mutable flow observations. The native initialization API
can derive this data without activating the destination. Selection errors and
panics deny before admission; native profiles require trusted context and
enforced security.

Retained request v3 and immutable request hash v3 freeze the selection at the
original begin. Context-only v2 and unbound v1 keep their exact historical bytes
and hash domains. Ordinary native-bound requests also retain their bounded
original material. Normal/nested begin, pre-dispatch return-context freezing,
raw-return recovery, caller-context decoding and collection compare configured
selection with original binding; retained identity is never fresh host authority.

Fresh native joins require an exact original selection inside the actual
operation/recovery transaction, independently of initialization verification.
Context-only operations cannot gain their first native mutation retroactively.
Historical record verification also checks a retained native selection when
present. Existing records remain history without rewriting the physical v29
schema or old initialization bytes. Owner rotation does not retarget the original
selection. This does not implement native dispatch or the complete caller profile.

Current focused evidence includes 38 native-state library tests, 21 kernel
binding tests and one real kernel-to-SQLite integration test. The integration
uses the actual begin, retained readback and recovery lease, rejects a different
valid initialization, and commits with the original selection. Its test-only
runtime probe then stops before dispatch, with zero tool invocations and zero
captured quota. The first kernel run expected an error where the kernel correctly
returned a signed deny; that assertion was corrected. The integration initially
used the callback's earlier timestamp as a lease decision clock; the existing
time-regression check rejected it, and the test now obtains a fresh trusted
time. No production clock or denial rule was weakened.

The 21-test kernel log is `/tmp/chio-native-binding-qualified.XnRp86.log`.
The final integration and strict all-target kernel/SQLite Clippy pass are at
`/tmp/chio-native-binding-integration.ZjCo28.log`. Rust hygiene/public surface,
security-CI and Apalache-slice checks, plus hygiene/public-surface mutation
self-tests, pass at `/tmp/chio-native-binding-static.QflcaV.log`. The additional
security-CI mutation self-test passes at
`/tmp/chio-native-binding-ci-selftest.Mkw5b4.log`.

The negative control temporarily removed both new authority-selection checks.
The first-write substitution regression then failed at the intended assertion:
the other authority successfully returned a committed flow snapshot. Its log is
`/tmp/chio-native-binding-negative.cHHvRL.log` (zero passed, one failed). Both
fixed production files were restored byte-for-byte before the broader rerun;
no mutant remains.

The restored substitution regression passes again in the broader rerun. The
current nonignored worktree fingerprint, including hidden files but excluding
this ledger and generated proof coverage, is
`3dbc214d24a04a2b6ecced145c144f0f4eb3160930d21085cad8a8518697b546`.
This is a local integrity check, not a signed release attestation.

The serial broader rerun at `/tmp/chio-native-binding-broad.JX70KH.log` was
interrupted with SIGINT after a new semantic row-change finding required a
regression. Its restored substitution control, full kernel library (1,338
passed), caller integration (21 passed, one ignored), nonce integration (17
passed), native integration (one passed), security-release integration (18
passed) and kernel SQLite integration (15 passed) completed successfully.
The runtime command incorrectly selected `--lib runtime_admission`, reporting
zero passed and ten filtered tests. That result is not qualification; the
required target is `--test runtime_admission`. Control-plane compilation was
interrupted, and subsequent strict Clippy, formal/proof-coverage, formatting and
full SQLite stages did not run. A corrected gate must reject zero-test success.
The preceding milestone's 3,286-entry total is not a current-source result for
this change. The binding graph refresh completed at
`/tmp/chio-native-binding-graph-final.2k60f7.log` with 163,666 nodes, 425,980 edges
and 7,012 communities. The subsequent semantic row-policy change needs a new
graph refresh.

The worktree currently has 584 changed/untracked files across eleven review
slices with none unclassified. HEAD and Cargo.lock remain unchanged from the
preceding checkpoint. All work remains local to the isolated launch worktree;
no commit, push, hosted job, workflow pin, merge, publication or operator
activation occurred. Native egress/declassification custody, dispatch-ledger
attachment, the complete original/caller profile, legacy consumers and the full
original protocol, active-defense, enterprise, platform, pilot and release
qualification scope remain open. The goal remains active.

### Native monotone row policy and snapshot consistency

The next adversarial probe reproduced a committed label downgrade inside a
nested trigger. The native callback previously checked authority, the join-table
allowlist and the absence of deletions, but those checks alone did not establish
monotonicity. A valid canonical BLOB label and matching digest changed a stored
principal label from Top to bottom while the join returned an apparently valid
Top snapshot. The pre-fix regression failed at that success assertion in
`/tmp/chio-native-monotonicity-before.LGaUsB.log` (zero passed, one failed).
An earlier fixture used TEXT in a STRICT BLOB column and was rejected by SQLite;
that earlier passing run is not evidence of the semantic finding.

A private shared row policy now validates live capture and immutable history.
Every row binds the original typed join's tenant and permitted identities;
identity and evidence columns cannot change on update. Generations are positive,
I-JSON-safe and nonregressing. Labels must be canonical, hash-valid and at least
as restrictive as both the requested join and their predecessor. After the
domain mutation, an independent scoped read must exactly match the returned
snapshot before the owning transaction can be returned. Any violation rolls
back the transaction and its row-change history. History remains evidence, not
a replayable command or present authority; malformed history is never repaired.
The affine lease owner and callback-disable guard remain intact. This change
does not alter physical v29 schema, initialization bytes or legacy flow behavior,
and grants no egress, declassification or dispatch authority.

Four focused regressions pass in
`/tmp/chio-native-monotonicity-qualified.4RMqhg.log`: nested principal, lineage
and session downgrades; generation, identity, tenant and transition corruption;
returned-snapshot mismatch; and historical predecessor downgrades when the
requested join is bottom. The capacity fixture was corrected too: unrelated
transition inserts would now hit the row-policy guard before reaching the
capture bound. It now uses otherwise valid same-identity updates and an
independent test counter, proving that the 4,096th update attempt is rejected
after the genesis row and 4,095 updates fill the 4,096-image budget. Rollback and
a clean retry both pass. Strict all-target kernel/SQLite Clippy passes in the
same log. Rust hygiene/public-surface, security-CI, Apalache-slice and diff checks
pass at `/tmp/chio-native-monotonicity-static.u2OfL0.log`.

The corrected serial broad run is in progress at
`/tmp/chio-native-monotonicity-broad.FA4LXk.log`. Its test wrapper rejects a
zero-test success, with positive and negative detector self-checks before the
queue. The correct runtime integration target has completed with 82 passed,
and the control-plane security filter completed with 234 passed.
Caller integration (21 passed, one ignored), nonce integration (17 passed),
native integration (one passed), release integration (18 passed), full kernel
library (1,338 passed), kernel SQLite integration (15 passed) and native state
(42 passed) have also completed. Five-package strict all-target Clippy, 110
formal mirror bindings, generated coverage regeneration/check (58 rows and 168
artifacts), 22 xtask formal-mirror tests and formatting pass. These are mirror
and coverage checks, not a new abstract-model proof. The full SQLite library
suite subsequently completed with 1,577 passed and three existing ignores in
2,342.87 seconds. The full queue exited successfully. Its nine distinct
behavioral targets total 3,303 passing entries and four existing ignores;
focused repeats, xtask tests, zero-test targets and nested child summaries are
not additional behavioral coverage. This qualifies the native monotonicity
baseline, not the four runtime-selection regressions added afterward or their
pending production fix. The earlier interrupted broad run is not part of this
total. The graph refresh
completed at `/tmp/chio-native-monotonicity-graph.AZe9PB.log` with 163,658 nodes,
426,060 edges and 6,976 communities.

The nonignored source fingerprint, including hidden files but excluding this
ledger and generated proof coverage, is
`141d57a7c2d4e84eb01dca2027bf60071acea69214b7e882a5ee4a9f4e76037b`.
There are 586 changed/untracked files across eleven review slices, with none
unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3` and
Cargo.lock remains unchanged. All changes are local and uncommitted. No hosted
qualification, publication or operator activation has occurred. Native egress
and declassification custody, complete original participant selection, external
start, release policy, legacy consumers and the full original roadmap remain
open. The goal remains active.

### Required flow gate covers native authority custody

The required information-flow gate now includes three exact inventories for
native flow custody (42 entries), original security authority selection (20)
and the real kernel-to-SQLite native binding integration (one). The existing
compiled-list/execution verifier enforces each name, passing disposition and
summary; missing, additional, ignored or filtered-away entries cannot qualify.
The gate uses `umask 022` and serial harness execution while preserving tests'
explicit thread and independent-process races. Its original 33 inventories,
WASM checks and positive/negative information-flow model checks remain required.

The contract first rejected the absent native inventories in
`/tmp/chio-native-flow-gate-before.gUnt2h.log`. Contract validation now shares
one parser/validator between the actual script and nine mutations: each omitted
native inventory, the existing adapter omission, an incorrect or widened native
filter, an ignored-only invocation, a changed integration target kind and a
changed filtering policy. This replaces a separate missing-label predicate
that did not exercise the actual contract validator. Exact-runner/verifier
self-tests also pass, including zero, missing, duplicate, renamed, extra and
ignored test cases. The initial contract log is
`/tmp/chio-native-flow-gate-contract.nEcwgZ.log`; the strict rerun including
security-CI mutation tests passes at
`/tmp/chio-native-flow-gate-static.IhzWfX.log`.

All three declared inventories match current compiled discovery and actual
passing output through the shared exact verifier. Evidence is at
`/tmp/chio-native-flow-inventory.iJJvE5/verification.log`. This reused the
completed 42-test native-state output from the broad queue and directly ran the
current compiled kernel binding target (20 passed) and integration target (one
passed), without a second Cargo invocation. Those repeated entries add no new
coverage to the broad totals. It verifies these new inventories, not completion
of the entire flow/formal script or hosted CI. Only gate scripts changed during
the broad Rust run; the Rust implementation under test is unchanged.

The graph refresh completed at
`/tmp/chio-native-flow-gate-graph.aamI4m.log` with 163,660 nodes, 426,062 edges and
6,972 communities. The source fingerprint, excluding
this ledger and generated proof coverage, is
`14515a8fc903a291fdc8122307663fd5d6ea7d7432f77266e8394ef36b4a7574`.
The worktree now contains 588 changed/untracked files in eleven review slices,
with none unclassified. HEAD and Cargo.lock are unchanged, and no hosted job,
workflow pin, publication or operator activation was performed. The complete
native dispatch lifecycle and remaining original roadmap requirements remain
open; the goal is active.

### Runtime selection containment and retained cleanup

The custody review found direct, uncontained runtime-authority selection
callbacks in original admission, runtime evaluation and reservation release.
The final revalidation path already contained its selection callback. The
reservation-release router also consulted the current hook before deciding to
release an attached runtime ledger: an absent hook or a legacy selection could
return without releasing that retained owner.

Four coordinator regressions require contained selection failures before
admission/evaluation/release and exact retained-ledger cleanup regardless of a
missing, legacy or panicking current hook. Independent counters forbid a legacy
evaluation, release or diagnostic callback even if a later catch would hide its
panic. Repeating cleanup must not release twice. These tests use the existing
coordinator doubles, not a physical SQLite store.

After the complete native-monotonicity baseline terminated successfully, the
original four regressions failed against unchanged production in
`/tmp/chio-runtime-selection-before.IVJvqA.log`: zero passed, four failed,
with Cargo exit 101. SHA-256 checks confirmed the three production files were
byte-identical before and after reproduction. Three failures were escaping
selection panics; the fourth observed zero releases for an attached ledger.

The kernel now uses one contained selector returning `Result<Option<&Binding>>`:
a failed callback is an error, never a missing selection or legacy fallback.
Original admission, runtime evaluation and final revalidation use that helper.
Release checks retained ledger custody before current hook configuration and
uses the existing operation-owned recovery path. Missing-ledger selection
failure still denies. No schema, request hash format or activation changed.

The initial fix passed all four regressions and all ten runtime-participant
coordinator tests, plus strict kernel all-target Clippy, at
`/tmp/chio-runtime-selection-focused.f0bXS7.log`. The four tests then passed
again with diagnostic-callback and repeated-cleanup assertions at
`/tmp/chio-runtime-selection-refined.5KfMfT.log`. These are overlapping runs,
not fourteen or eighteen distinct new tests. The earlier 3,303-entry baseline
does not qualify this fix.

The post-fix queue at `/tmp/chio-runtime-selection-broad.SbVHK9.log` completed
successfully: 1,342 kernel library tests, 82 runtime-admission integration tests,
15 kernel SQLite integration tests and 18 security-release recovery tests pass.
Strict all-target Clippy for kernel, runtime-core, store-sqlite and xtask passes,
as does workspace formatting. The SQLite `runtime_participant` filter matched
zero tests and is explicitly excluded from qualification. The corrected
`admission_operation_store::tests::runtime_replay::` selection completed at
`/tmp/chio-runtime-selection-replay-exact.rjMOtX.log`. Its gate checks the exact
compiled and executed 37-name inventory with SHA-256
`8bcff49eca03cc2a9da8899f3106e8223ee37be59d069fe4b3c6172a5415f9d8`,
not just a successful Cargo exit. All 37 tests pass with zero failed or ignored
tests in 114.72 seconds, and the exact-inventory verifier passes. Together these
five distinct suites provide 1,494 passing post-fix behavioral test entries;
the four focused regressions, ten-test coordinator run and 22 checker tests are
not added to that count.

The replay queue then rejected stale generated coverage: the reviewed
`formal/MAPPING.md` update changed its input digest. This was not a runtime-test
or source-mirror failure. Final coverage regeneration and checks are recorded
at `/tmp/chio-runtime-selection-coverage-final.iG41YR.log`: 58 rows, 168
artifacts, all 110 source mirrors and the final diff check pass. This closes
the local runtime-selection fix checkpoint, not the full workspace, native
dispatch lifecycle, formal refinement, hosted qualification or launch gates.

The source check rejected exactly three changed mirror entries. Reviewed drift
is limited to revalidation, release, runtime evaluation and the new required
selector anchor. The model abstraction is unchanged: hash reconciliation is
not a new model proof or complete original-profile pinning. Source-check and
coverage reconciliation is recorded in
`/tmp/chio-runtime-selection-mirrors.uVyp1z.log`: 110 mirror entries, 58
coverage rows, 168 artifacts and 22 checker tests pass. The empty filtered
xtask integration targets do not add test evidence. Final hygiene,
public-surface, security-CI, Apalache structure, exact-flow-gate self-test and
diff checks pass at `/tmp/chio-runtime-selection-static-final.yYzb0n.log`.
The final graph update at `/tmp/chio-runtime-selection-graph-final.1CEh7x.log`
completed with 163,681 nodes, 426,105 edges and 7,004 communities.

The caller-dispatch design now records the actual phase boundary: the existing
last-moment hook runs after `CapturePending`, whereas the first native join
requires `BrokerAttemptRegistered`. A native integration needs preparation and
operation-owned acquisition before budget authorization, with distinct egress
custody carried to final dispatch. It cannot relax the join phase, reconstruct
the full live-request commitment from credential-stripped retained material, or use
historical join/fence readback as fresh authority.

The corrected source fingerprint, excluding this ledger and generated
coverage, is `57f3fa9209ed1133e2530d1c0861a6c1c824c3a41202b2b07e5ec374fcc15c7a`.
All 589 changed/untracked files map to eleven review slices, with none
unclassified. HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3` and
Cargo.lock remains unchanged at SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
Changes remain local and uncommitted. No hosted, operator, release or activation
action was performed. The full original roadmap and qualification requirements
remain open and the goal remains active.

### Original operation authority profile (local qualification)

The sequence below preserves the initial reproductions and intermediate failed
runs. The final local qualification table applies to the completed selector fix;
it is not full-workspace, hosted or operator qualification.

The original request hash did not include runtime authority or migration
generation. Two coordinator regressions reproduced reuse of the same operation
after changing either selection on unchanged production:
`/tmp/chio-authority-profile-before.OAJxe2.log`, zero passed and two failed,
Cargo exit 101. The coordinator and retained-request sources were unchanged at
SHA-256 `5696d14925ebe5cb23a0f47b9e167d8070f4b9c49715d13b5fbf345231f05724`
and `e3cd9249d1d8ea5d1f9a9ba079a05a411666c4c3069946106686f43b3587f929`.

New retained admissions now use v4 and commit to a validated, data-only
`AdmissionAuthorityProfileV1`: runtime hook presence and declarations, required
swarm policy, runtime/approval identities and migration expectations, and the
DPoP replay domain with freshness policy. Absent authorities are explicit fields,
not missing-field defaults. The v4 hash wraps the prior immutable request hash,
so stable security identity and native initialization remain bound. Legacy
v1-v3 canonical bytes remain readable; no stored profile is backfilled and no
physical database schema or activation is changed. Non-retained legacy requests
do not gain operation-owned custody through this format.

Kernel checks cover original begin, pre-budget admission, prepared-credential
origin, runtime acquisition, final revalidation, return-context freezing and
caller decoding/collection. SQLite runtime, approval and DPoP claims compare
their actual intent with the original profile inside the operation-lease
transaction. A first native mutation requires the profile; historical native
join retries still return historical data. Post-effect recovery reloads original
request material through an exact fenced operation read, rather than discarding
it or inferring a profile from current configuration. Retained cleanup remains
independent of current hook selection.

The first full kernel run identified seven integration failures: new native
admission expectations still named v3, finalization recovery discarded original
material, and early profile validation displaced specific signed swarm denials.
The implementation and current-format expectations were corrected without
changing legacy codec vectors or the existing swarm-denial assertions. An unmet
required-swarm policy is representable configuration data, not admission.
The corrected kernel passed 1,347 tests, then 1,348 after adding independent
hash coverage for the original authority fields. The shared prepared-credential
origin check and its replacement-hook regression now pass in the complete
1,349-test kernel suite at `/tmp/chio-authority-profile-positive.oxwyNw.log`
(zero failed or ignored). The preceding attempt at
`/tmp/chio-authority-profile-origin.ux41lY.log` failed to compile a test that read
a private coordinator field; the regression now reads the original request
from the test store without broadening production visibility.

At `/tmp/chio-authority-profile-recovery.5CIeW1.log`, the 38-test runtime replay
suite passed 37 and failed one preflight fixture that still constructed v1
material before a new claim. That fixture now selects the original profile
before begin. The rerun at `/tmp/chio-authority-profile-store.mCx80v.log`
closed successfully: runtime replay 38, governed approval replay 46, DPoP replay
61 and native mutations 25, all passed with no ignored tests. The new
physical-store regression confirms that later import cannot upgrade either an
explicitly absent runtime selection or a legacy request without a profile.
The 25 native mutation tests are not the complete 42-test native inventory.
That run did not yet qualify complete native coverage, live integration,
source mirrors, coverage, strict Clippy or final formatting. Subsequent runs
are recorded below.

The permanent flow gate now names seven profile codec/kernel regressions and the
physical non-upgrade regression, bringing its exact inventories to 38. The
contract self-test passes at `/tmp/chio-authority-profile-static.xFhKzb.log`,
alongside hygiene, public-surface, security-CI and Apalache structure checks.
Both new inventories compiled and executed at
`/tmp/chio-authority-profile-positive.oxwyNw.log` (seven plus one exact tests).
These are focused repeats, not additional tests on top of their full suites.
Seven new required source anchors and the configured approval getter are
registered. In addition to the profile codec, retained hash and coordinator,
these include the actual SQLite runtime, approval and DPoP claim entry points
and intent comparisons, and the native join's original-request check. The
kernel forwarding paths alone do not cover those enforcement decisions.
The first mirror check rejected the getter's hash-entry ordering;
after correcting the ordering, the checker reports the expected implementation
drift at `/tmp/chio-authority-profile-mirror-drift.log`. Hash reconciliation
was still pending at that point and does not claim model refinement.
The graph refresh at `/tmp/chio-authority-profile-graph.zVx81n.log`
also predates later edits and cannot serve as the final refresh.

Two negative controls completed at
`/tmp/chio-authority-profile-controls.8QZiVm.log`. Removing the prepared-origin
profile comparison failed its one selected regression; independently removing
the physical runtime intent/profile comparison failed the non-upgrade
regression. Each test command exited 101 with zero passed and one failed, not
a compile failure or an empty filter. The latter assertion checks the required
profile rejection; its output does not independently report a committed SQL
write. Both production files were restored byte-for-byte, at SHA-256
`a40a170ff5421c098fa0087aa09517840ab06e4adee2176c4cf0b3d08300b0db`
and `8d34fbbaaa39fc3b29df97579f837759180755f79e24dbe5565e1856120dba81`.
No mutant remains active. Fresh full-kernel, exact inventory, native, live
runtime, caller/recovery, control-plane and strict Clippy checks were queued at
`/tmp/chio-authority-profile-integration.qnNKB0.log`; their results follow.

That integration queue closed with one new-format expectation failure. Kernel
1,349, live runtime 82, kernel/SQLite recovery 15, native custody 42 and caller
21 all passed. The caller's external-start counterexample remains ignored.
Nonce lifecycle passed 16 and failed one assertion still expecting v2 for a
new v4 preflight. The assertion now requires v4 and a retained profile, while
its restart, exact-byte, denial and single-invocation checks remain intact.
Native admission integration, final-release recovery, control-plane, Clippy,
the new exact inventories and mirror qualification were not reached in that
queue. None is inferred from its earlier successes.

Further admission-selector review found a separate native fallback defect.
At `/tmp/chio-native-mode-before.jdwQ4A.log`, six selected kernel tests ran:
four passed and two new regressions failed because an explicitly selected
native authority could return no durable admission, including without a durable
store. The coordinator remained at SHA-256
`3fc6e60402a602a12dc5bd929e464ee62fcd2b980204524b11035b6f736f6315`
before and after this negative run. Native selection now forces structured,
retained admission independently of ordinary mode coverage and rejects missing
storage rather than using ephemeral fallback. This does not acquire native
egress or declassification custody. The permanent security-selection inventory
now names 22 tests; the gate still has 38 inventories. Coordinator begin and its
hash wrapper are required drift anchors as well as their callees. Qualification
of this latest production change first stopped at formatting, before compiling
or running tests (`/tmp/chio-native-mode-after.JEQEwR.log`). Coverage, store
requirements and retention now share one authority-admission predicate, so a
new selection cannot be added to one condition while omitted from another.
The formatted-source rerun is at `/tmp/chio-native-mode-verified.xZwjH8.log`;
previous kernel totals do not qualify the later selector fix.

That rerun passed the 1,351-test kernel, 82 live runtime integrations, 15
kernel/SQLite recovery tests and all 17 nonce lifecycle tests. Native admission
integration then exposed its remaining fresh-v3 expectation. It now requires
v4 and a profile, preserving the actual original binding, leased native join,
physical readback, zero-dispatch and zero-budget assertions. The remaining
v1-v3 references in crates, SDKs and tests were checked and left as deliberate
historical codec or fixture inputs.

At `/tmp/chio-profile-closeout.ULIkWE.log`, native admission integration and
all 18 final-release recovery tests passed. The three permanent inventories
executed from the actual flow-gate definitions passed with 22, seven and one
tests. The initial `security::tests` control-plane filter selected only two
top-level tests, not the full security module selection. The corrected
`security::` run at `/tmp/chio-profile-final-gates.592C6C.log` passed all 234
enumerated tests. The narrower run is not additional coverage.

Final local behavioral qualification on the completed selector source:

| Scope | Passed |
| --- | ---: |
| Complete kernel library | 1,351 |
| Live runtime admission integration | 82 |
| Kernel/SQLite durable recovery | 15 |
| Durable nonce kernel lifecycle | 17 |
| Actual native admission/join integration | 1 |
| Final-release recovery | 18 |
| Control-plane security selection | 234 |
| Physical runtime-profile non-upgrade regression | 1 |

These are 1,719 distinct selected behavioral tests, with zero ignored in these
final targets. The 22 and seven exact kernel inventories repeat tests already
included in the full kernel result. Earlier physical replay/native and caller
results above predate the final selector fix and are not represented as a fresh
complete suite; the caller's ignored external-start counterexample remains open.

Strict all-target Clippy passed for kernel, runtime-core, SQLite, control-plane
and xtask with warnings denied. All 22 selected mirror-checker tests passed;
unrelated integration binaries filtered to zero are not qualification evidence.
After reviewing the unchanged model abstractions, 22 of 117 mirror entries were
reconciled. An independent before/after comparison verified that only SHA-256
values changed, with no residual placeholder hashes. All 117 entries match.
Generated coverage matches 58 rows and 168 artifacts. Final formatting and
`git diff --check` passed in the final-gates queue, which exited zero. No model
transition, resource bound or proof assumption changed.

The final code graph refresh is at `/tmp/chio-profile-closeout-graph.log`
(163,754 nodes and 426,326 edges). The final static batch at
`/tmp/chio-profile-final-static.gjh3Fm.log` passed Rust hygiene, public-surface,
security-CI, Apalache structure and the 38-inventory flow-gate contract, plus
`git diff --check`. All 594 changed/untracked files map to eleven review slices,
with none unclassified. The source fingerprint, excluding this ledger
and generated coverage, is
`3a75b22c7f1a66e5a7724bf61d33f6584bad8950c60994403cab37172c904e1a`.
The coordinator is at SHA-256
`d0939c38f3f1776b58d930c7586f7e2aeebf249bad0eecf393455ae5f9913ccf`.
HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`. Cargo.lock is unchanged
from the preceding local snapshot at SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`;
its pre-existing uncommitted changes relative to HEAD were preserved.

The next native lifecycle must preserve the existing one-join-per-operation
journal (`admission_operation_security_participant_mutations.sql` keeps
`UNIQUE(operation_id)`) and use separate typed custody history for subsequent
claims and outcomes. The legacy `FlowStateStore` exposes acquire, validate and
commit, but no release method. Declassification `Released` is an outcome, not
permission to mint another use: `declassification/uses.rs` retains consumption
and returns `AlreadyConsumed` on an exact retry, with outcome evidence linked
to its predecessor. Operation-owned cleanup must preserve these semantics and
must not turn expired, failed, released or outcome-unknown history into fresh
authority. This boundary review is not implementation of native egress or
declassification custody.

Changes remain local and uncommitted on `security/launch-integration`, with no
commit, push, merge, hosted job, publication or operator activation. The complete
original roadmap remains active, including native egress/declassification
custody, authenticated external start, remaining caller/executor work, legacy
consumers, full qualification and operator launch gates.

### Kernel-owned native flow preparation (local qualification)

The selected native authority now has a kernel-created, call-scoped
`NativeSecurityFlowJoinAuthority` at ordinary and nested dispatch preparation.
The trusted hook supplies labels and a transition identifier, not an operation,
destination, flow identity, decision clock or recovery lease. The coordinator
checks original immutable request material and v4 selections before the callback,
loads the actual retained operation under its serving fence and acquires its
lease before invoking the native store port. SQLite resolves the initialization
independently and rechecks the actual operation lease inside the existing join
transaction. Complete command/result history and the current operation are
read together under the fence, then compared again at callback completion.

The default native preparation callback denies. A silent success, swallowed
error, second join, changed command/selection/operation, missing history or
different acknowledgement cannot reach runtime claims or dispatch budget capture.
Store and hook panics are contained, including recovery-lease acquisition inside
the mutation sequencer. Denial does not undo a committed monotone join. Historical
results do not become live egress observations or permission to dispatch.

The existing `BrokerAttemptRegistered` phase, one-join-per-operation journal,
physical SQL write whitelist, v29 schema and old initialization bytes are
unchanged. Native nonce preflight in `Prepared` denies before budget or issuance:
it needs its own typed custody rather than borrowed dispatch authority. Explicit
native activation, egress acquire/commit, declassification consumption/outcomes,
dispatch-ledger binding and general participant recovery remain unimplemented.
No production native adapter or operator source has been activated by this work.

Two implementation regressions were reproduced before their checks were fixed:

- `/tmp/chio-native-owner-before-origin-3.log` ran three coordinator tests: two
  passed and the substituted-original-request case failed. The fresh entry point
  accepted altered request material despite the correct operation and identity.
  `/tmp/chio-native-owner-after-origin.log` then passed all three cases after
  adding the original material comparison before the callback.
- `/tmp/chio-native-owner-lease-before-2.log` executed the exact lease-panic
  regression and failed because a subsequent valid preparation encountered a
  poisoned mutation sequencer. Lease callback unwinding is now contained before
  leaving that lock's scope; the original failure still denies the command.

Intermediate compiler failures and the initial zero-match test filter are not
behavioral evidence. The final serial qualification queue exited zero. Its
captured output is `/tmp/chio-native-owner-qualification.log`, SHA-256
`0a9856dda503cdebf3140b19881b1b59896a918f948838e4b8c9e5972218d052`.
The completed source has these distinct selected test results:

| Scope | Passed |
| --- | ---: |
| Complete kernel library | 1,356 |
| Actual native admission/join integration | 6 |
| Native state, schema, ownership and recovery | 42 |
| Live runtime admission integration | 82 |
| Kernel/SQLite durable recovery | 15 |
| Durable nonce kernel lifecycle | 17 |
| Final-release recovery | 18 |
| Control-plane security selection | 234 |

All 1,770 selected behavioral test entries passed with none failed or ignored.
This is not a full SQLite library, full workspace, platform or operator run.
Strict all-target Clippy passed for kernel, runtime-core, SQLite, control-plane
and xtask. The 20 selected mirror-checker tests also passed; their unrelated
zero-match integration binaries are not evidence and are not counted.

The permanent flow gate contains 39 exact inventories. The final-gates queue at
`/tmp/chio-native-owner-final-gates.log` passed the actual gate definitions for
original security selection (22), native admission integration (six) and the
kernel-owned preparation contract (five). These repeat tests above and are not
added to the total. The native integration rerun uses the final test source after
removing its unused legacy lease-extension import. The 42 logged native-state
test identities were independently compared with the permanent gate's exact
inventory and matched.

Five new mandatory source anchors cover the handle, portable history type/port,
SQLite forwarding and fenced readback. The source check first rejected nine
entries (four changed caller/admission anchors plus five new ones). After
reviewing the unchanged revocation gate and atomic `Admit` abstraction, those
nine of 122 entries were reconciled. An independent raw manifest comparison
verified hash-only changes, with no remaining placeholder hashes. All 122
entries match. No model transition, bound or assumption changed; this is not a
proof of native acquisition, SQL refinement, activation or general recovery.
Generated coverage matches 58 rows and 168 artifacts.

The final-gates queue exited zero after formatting, diff hygiene, Rust file and
public-surface checks, security-CI and Apalache structure checks, and the
39-inventory contract test. All 597 changed/untracked files map to eleven review
slices, with none unclassified. The source fingerprint excluding this ledger
and generated coverage is
`4665f869c6770ead7f6b92d8ad21c8662ddf01dd5e10ac83bfe354d336dd4b91`.
The native coordinator is at SHA-256
`254456f7eb9ddfd88b7de153a1a9690c485e3a4f0e1bd5712f3af2280e97d5f1`.
HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`. Cargo.lock retains its
preceding local SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`;
its pre-existing uncommitted changes relative to HEAD were preserved.

The final code graph update completed at
`/tmp/chio-native-owner-final-graph.log`, with 163,833 nodes, 426,588 edges and
7,011 communities. Native preparation remains before runtime claims and budget;
the original physical monotone journal has not been widened into a lifecycle
writer. The full original roadmap remains active, including dedicated native
nonce/egress/declassification custody, explicit activation, authenticated caller
start, complete executor/caller integration, legacy consumers, full qualification
and operator launch gates. Changes remain local and uncommitted; no publication,
hosted job, source activation or operator migration occurred.

### Shared recovery-lease containment (local qualification)

The native-only recovery lease catch left the same boundary exposed in other
admission paths. `QualifiedAdmissionOperationStoreExt::claim_recovery` invoked
claim persistence, operation readback and final claim revalidation without
containing an unwind. A callback could therefore unwind through a caller's
mutation sequencer before lease qualification completed.

Four regression entries first failed for the intended escaping panic, covering
the claim callback before and after persistence, the operation read, and final
revalidation. The ordinary stale-version/fence error test passed unchanged.
The runtime acquisition regression also failed with an escaping post-write
claim panic. Reproduction logs are `/tmp/chio-shared-lease-before.log` and
`/tmp/chio-shared-lease-runtime-before.log`; both test commands exited 101.

The non-overridable shared qualification boundary now contains those unwinds
and returns `AdmissionOperationStoreError::OutcomeUnknown`. It mints no opaque
lease from an uncertain result, does not clear a possibly durable claim, and
does not turn a panic into evidence of rollback. All existing qualification
checks and ordinary error results remain intact. This does not repair backend
state, contain process-aborting failures, or establish containment of unrelated
store callbacks. The native coordinator now uses this shared boundary instead
of its redundant lease-only catch.

One atomic, one-shot fault controller replaces the native-specific lease panic
flag and is shared by the qualification and runtime tests. Fault injection
releases fixture state locks before panicking. The tests require retained claim
evidence after write, unchanged operation state, no invocation, no lease on
panic, a usable caller sequencer and successful fresh qualification. A runtime
verifier that swallows the failed claim still cannot return an accepted Allow;
subsequent compensation traverses the real kernel sequencer successfully. These
fixture contracts are not physical backend qualification.

The current local behavioral selection is:

| Target | Passed | Ignored |
| --- | ---: | ---: |
| Kernel library, including six new regressions | 1,362 | 0 |
| SQLite admission-store library selection | 429 | 0 |
| Caller execution | 21 | 1 |
| Kernel nonce lifecycle | 17 | 0 |
| Remote delivery | 11 | 0 |
| Native authority integration | 6 | 0 |
| Final-release recovery | 18 | 0 |
| Runtime admission integration | 82 | 0 |
| Control-plane security selection | 234 | 0 |
| Kernel/SQLite durable recovery | 15 | 0 |

All 2,195 executed behavioral entries passed. The one ignored caller test names
the unimplemented durable external-start handshake: a lost external report must
not permit a refund at nonce expiry. It is not passing evidence. These results
do not qualify the full workspace, full SQLite library, platform or operator
profile. Captured logs are `/tmp/chio-shared-lease-kernel-after.log`,
`/tmp/chio-shared-lease-qualification.log` and
`/tmp/chio-shared-lease-source-before.log`. The last log also captures the
subsequent expected source-mirror rejection; its exit status is one, not a
failed kernel/SQLite test.

Strict all-target Clippy passed for kernel, runtime-core, SQLite, control-plane
and xtask. All 20 selected mirror-checker tests passed, including independent
enforcement of each required source symbol. The two unrelated zero-match xtask
integration binaries are not counted as executed evidence.

The permanent flow gate now requires 41 exact inventories, including five
shared-boundary entries and the runtime regression. The portable store mirror
also requires the extension-trait implementation, not just the store port.
PostAdmissionDropGuard still abstracts admission as atomic resource reservation
and does not model callback unwinds, mutex poisoning or a physical claim
journal. Source-drift reconciliation is not a new refinement or liveness proof.

The source check rejected exactly the shared qualification trait and native
`join_once` anchors. After reviewing the unchanged model abstraction, two of
122 mirror entries were reconciled. An independent raw-manifest comparison
confirmed hash-only changes and no remaining placeholder hashes. All 122
entries match, and generated coverage matches 58 rows and 168 artifacts.

The final queue at `/tmp/chio-shared-lease-final-gates.log` exited zero. It ran
the actual permanent gate definitions for native integration (six), shared
qualification (five), runtime lease containment (one) and native preparation
(five). These 17 repeat entries are not added to the behavioral total. The
other flow inventories were not rerun as a complete flow qualification. The
41-inventory contract test, formatting including the new included test files,
Rust file/public-surface checks, security-CI and Apalache structure checks, and
diff hygiene passed. Exact-inventory negative-control self-tests also passed
in `/tmp/chio-shared-lease-structural.log`.

All 598 changed/untracked files map to eleven review slices with none
unclassified. The source fingerprint excluding this ledger and generated
coverage is
`7d2cb4356615ce05cd1bb74aacb1e70be023ebc898f3636102bd75a0d93834dc`.
The shared store source is at SHA-256
`436662bd9630dc5eb1880c11a516ef5bc28cbc08df2934f52397b1bf1df5a408`;
the native coordinator is at
`44ffb2f38b2ce066b4f47def885ac26e197ce8b21fabcd6e86c01ed4ca0da1fc`.
The main qualification log SHA-256 is
`e2a035d9a46d7ce962789ac3f3021e387bcaddda6fed1d9fdbb7e8634a77886c`;
the kernel library log is
`6de3d65426bbeb7ab91b7105c6467da7211e3b14aa9c35a5b6dc53c02b9ea950`.
HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`, and Cargo.lock keeps
its preceding local SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`, including
its pre-existing uncommitted changes relative to HEAD. The code graph update
completed at `/tmp/chio-shared-lease-graph.log` with 163,849 nodes, 426,630 edges
and 6,978 communities.

No schema, native write phase, journal whitelist, activation or external-start
permission changed. Dedicated native nonce/egress/declassification custody,
authenticated caller start, executor integration, full platform qualification
and operator promotion remain required. The full roadmap goal stays active;
these changes remain local and uncommitted.

### Prepared live-request binding (selected local qualification)

The native egress review corrected a hash-role misconception in the caller
dispatch design. The existing flow resolver and declassification grant bind
canonical argument payload bytes. The pre-dispatch port independently compares
the full canonical live request. Replacing the grant's payload commitment with
the digest of an envelope containing that same grant would introduce a
self-reference and change the established grant contract.

`PreparedFlowDispatch` now borrows its original request and retains a separate
full-envelope digest. Its explicit equality check rejects replacement request,
agent, server, tool, origin, capability or transient grant data even when the
arguments are identical. Commit rechecks the borrowed request before participant
mutation. The digest is data, not credential verification, operation ownership
or execution authority. It does not replace the credential-stripped retained
admission material digest. No signed payload or database schema changed.

The focused run at `/tmp/chio-native-egress-request-binding-3.log` passed all
13 prepared-dispatch behavioral tests and two compile-fail doc tests. The doc
tests failed compilation for their intended reasons: reuse after consuming
commit (`E0382`) and mutation of the borrowed live request (`E0502`). An initial
filename-based filter matched zero tests and is explicitly excluded from
verification; the active module is `security::adapters::tests::prepared_dispatch`.

The payload-only negative control at `/tmp/chio-live-request-negative.log`
compiled successfully and failed all three new regressions, with zero passed.
It failed the independently computed envelope digest, equal-argument envelope
substitution, and stripped transient-grant checks. Full-request hashing was
restored before broader qualification. The original valid grant still commits
and records its terminal outcome using its unchanged payload commitment.

The required flow gate now inventories all 13 prepared-dispatch tests by their
actual names. Its structural contract checks 42 exact groups and rejects missing,
broadened, ignored-only or filename-based prepared-dispatch targets. Three new
source anchors cover the full-request hash helper, digest accessor and equality
check. These are source-drift checks, not a formal model of canonical request or
credential binding. The follow-up at
`/tmp/chio-live-request-qualification-after-stack.log` passed 237
security-filtered control-plane tests, the repaired retraction scenario, both
compile-fail docs, strict all-target Clippy for `chio-control-plane` and `xtask`,
and all 20 mirror-checker tests. It then stopped on the intended source drift in
the request-binding implementation. The review at `/tmp/chio-live-request-mirrors.log`
updated one of 122 mirror entries; comparison against the fresh pre-bless
manifest verified that only hash values changed. Coverage regeneration and its
check both report 58 rows and 168 artifacts.

The first full library attempt at `/tmp/chio-live-request-qualification.log`
aborted in `finding_status_retraction` after 820 tests passed. It did not reach
the queued doc, Clippy or mirror commands and is not a passing library result.
The exact isolated rerun at `/tmp/chio-retraction-stack-before.log` also aborted.
Debugger evidence at `/tmp/chio-retraction-stack-current-thread.log` and
`/tmp/chio-retraction-stack-frames.log` shows a large composed test future above
the blocking kernel finalization and retained-request decoder, rather than an
unbounded recursive call chain. A new future-size regression failed at
`/tmp/chio-retraction-future-budget-before.log`, reporting 57,912 inline bytes.
The shared test helper now constructs a boxed scenario before returning to its
caller. Its returned future stays pointer-sized rather than embedding the large
scenario in each caller's poll frame. No stack limit, fixture or behavior
assertion was relaxed. The exact corrected scenario completed on the default
stack in 18.69 seconds at `/tmp/chio-live-request-qualification-after-stack.log`.
The complete fresh library rerun subsequently passed; the earlier aborted run
remains failed evidence and is not included in that result.

The fresh full-library run and exact 13-test dispatch inventory are recorded at
`/tmp/chio-live-request-full-rerun-and-native-negative.log`: all 1,000 library
tests passed, with zero ignored or filtered, in 1,172.96 seconds. The exact
13-test prepared-dispatch inventory also passed. Those repeated scoped tests
are not added to the library's distinct count. A new production SQLite
regression then followed it:
`native_join_only_hook_cannot_activate_dispatch`. Unlike the earlier preparation
probes, this case omits the test runtime denial and lets the legacy commit
callback return success. It requires zero connector calls, zero legacy commit
callbacks, denied output, restored quota and retained monotone join history.
The native integration inventory now requires seven names. The new boundary
test failed as intended: the response was `Allow`, and the connector was invoked
once without native lifecycle custody. This final regression made the command
queue exit 101; it does not invalidate the preceding complete library pass.
The native fix is qualified separately below.

The next native lifecycle implementation must keep the immutable join journal's
one-join-per-operation rule and its eight-table whitelist. Egress needs a
separate typed journal plus current-row recovery ordered by anchored global
commits across both command families. Neither the existing join-only replay nor
this prepared-request change supplies that writer. Native nonce, egress and
declassification custody, authenticated caller start, executor integration and
the complete release qualification remain required. No workflow, operator
database, activation or publication was changed. The full roadmap stays active.

### Native dispatch downgrade boundary (selected local qualification)

The real SQLite preparation probe exposed a join-only native hook entering
legacy dispatch. A successful monotone join and a generic callback returning
`Ok(None)` do not establish native request lifecycle ownership or activation.
The kernel now retains that distinction at its final pre-dispatch gate, before
legacy lifecycle callbacks, final budget capture and connector entry.

The gate reads the immutable original admission selection before consulting
the live hook. Removing the hook, hiding the current native selection, dropping
context or changing to optional policy cannot erase an existing native lifecycle
requirement. Live native selections also deny, and selector errors or panics
remain fail-closed. Both ordinary and nested evaluation pass the original
admission into this shared gate. Legacy requests without a native selection
keep their existing policy behavior.

Three new kernel regressions exercise original-selection downgrade attempts,
live-selection fallback/error/panic behavior, and actual nested join-only
dispatch. The earlier positive native join
case still requires matching acknowledgement and anchored readback, then reaches
the specific unsupported-lifecycle denial instead of the connector. Both exact
seven-test inventories, kernel preparation and real SQLite integration, passed
at `/tmp/chio-native-dispatch-gate-qualification.log`. The SQLite cases completed
in 20.34 seconds, with zero ignored or filtered. The bypass regression requires
the specific lifecycle denial, zero connector and legacy commit calls, restored
quota and retained monotone join history.

The subsequent full kernel attempt passed 1,361 tests and failed three recovery
fixtures that created their original native terminal/raw records through the
now-unsupported live dispatch path. The queue stopped there; its control-plane,
Clippy and mirror commands did not execute. Those fixtures now construct
already-returned history through internal storage primitives and explicitly
assert that the live final gate rejects the same admission. No connector is
called and no production bypass or activation switch was added. Original
selection mismatch, unchanged operation, exact receipt/output replay and raw
return recovery assertions remain required. All 11 focused native-authority
tests passed at `/tmp/chio-native-historical-recovery-fixture.log`. The permanent
kernel preparation inventory now contains eight tests, including the separate
nested entry regression; the SQLite inventory remains seven. The fresh complete
kernel run and broader qualification are recorded at
`/tmp/chio-native-dispatch-final-qualification.log`: all 1,365 kernel library tests
passed, with zero ignored or filtered, in 57.18 seconds. Both the eight-test native
inventory and the 22-test original-authority inventory passed separately and
are not added to the library count. The same queue passed all 82 runtime-admission,
17 nonce-lifecycle, 11 remote-delivery and 18 security-release tests. Caller
execution passed 21 tests with one existing ignored test: the authenticated
external-start handshake is still unimplemented. Control-plane and lint
qualification are tracked independently: all 237 security-filtered control-plane
tests passed in 115.45 seconds. Strict all-target Clippy for `chio-kernel`,
`chio-runtime-core`, `chio-store-sqlite`, `chio-control-plane` and `xtask` passed
with warnings denied. Including the seven real SQLite native cases, this slice
has 1,758 distinct selected
behavioral passes and one ignored caller-start requirement. Source anchors now
include the original selection accessors and stable binding validation, not only
the forwarding gate.

All 20 mirror-checker tests passed. The final queue then stopped on the intended
source drift, not a test or lint failure. Eight mirror entries across six source
files were reviewed against `PostAdmissionDropGuard` and
`RevocationPropagation`. The added refusal preserves pre-dispatch cleanup and
existing revocation checks; neither model proves native activation, exact native
row custody or complete external-start semantics. No model claim was expanded.
At `/tmp/chio-native-dispatch-mirrors.log`, eight of 123 entries were updated;
comparison with the fresh pre-bless manifest verified hash-only changes and no
remaining placeholder hashes. All 123 entries match, and generated coverage
remains 58 rows and 168 artifacts. Workspace formatting and diff checks passed.

The structural flow contract validates 42 exact inventories. This slice executed
the native preparation, original-authority and native SQLite inventories, not
the complete flow gate or workspace/release qualification. Hygiene, public
surface, exact-runner negative controls, security CI contracts and Apalache
structure checks also passed. The final code graph has 163,880 nodes and 426,753
edges. The worktree remains 599 changed/untracked files across 11 review slices,
with zero unclassified paths. The source fingerprint, excluding this ledger and
generated coverage, is
`ac1d3890f55d2c0c5bd0e10448cf3447dfcbe1252e8219df388927040eb9cd7d`.
The final qualification log SHA-256 is
`b85fe32ef32769f8823a8e9523dd9f35e9194d5aaa2b906fb5e3d2c8311513e2`.
The pre-existing 15 added lockfile lines are preserved, with lockfile SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

This is a fail-closed boundary,
not an implementation of native lifecycle custody. Dedicated nonce, egress,
declassification and recovery support remain open. The next native integration
also needs a fresh fenced flow observation, distinct from historical join
readback; it cannot require an already completed join merely to observe the
generation needed for that first join. No workflow, operator database, activation
or publication was changed. All changes remain local and uncommitted, and the
full roadmap goal stays active.

### Fresh native flow observation (selected local qualification)

Native initialization and historical join results did not supply the current
generation needed before an operation's first native join. The portable
`AdmissionOperationStore::observe_native_security_flow` port now returns a
data-only `NativeSecurityFlowObservationV1`; unsupported stores deny explicitly.
The SQLite implementation checks the current owner fence, independently observed
time, global anchor, complete native row/history coverage and exact selected
initialization in one read transaction. It creates no rows, global commits,
admission operations, recovery leases, activation or mutation authority.

The result distinguishes effective inherited labels from the exact persisted
context generation. A previously unjoined session can inherit principal/lineage
taint without having a context row. Its effective snapshot generation must not
stand in for `stored_context_generation()` at admission. Missing initialization
is an error, while a valid context without a stored generation is a successful
observation. Absence of an isolation epoch is not proof that future inherited
labels will be public. Every writer still checks current state and its actual
operation custody, and an observation can become stale immediately.

Five initial storage regressions failed for the intended unsupported-port reason
at `/tmp/chio-native-observation-before-2.log`. After implementation, all six
observation tests passed at `/tmp/chio-native-observation-after-2.log`, including
unanchored row tampering with exact triggers restored, imported-but-uninitialized
selection, wrong authority/fence/time, current-owner takeover, inherited taint,
historical-versus-current results and no-write footprints. Earlier compile-only
attempts are not behavioral evidence.

The real-kernel test keeps one capability lineage and varies only the request
identifier and observed generation. First and refreshed observations allow the
operation-owned monotone join; an old generation denies without another join.
All attempts retain the final unsupported-native-lifecycle denial or the earlier
stale-generation denial, zero connector and legacy commit calls, no output and
restored quota. The first two integration attempts failed because mandatory
history readback obscured a physical write denial with a missing-join error.
`join_once` now always performs that readback but preserves the original write
error. It still denies lost acknowledgements after a physical commit, no-op
writes, mismatched history and callback panics. The existing kernel fault test
now also requires readback after an explicit pre-write denial, preservation of
that original error, no recorded join and no budget capture or connector call.

At `/tmp/chio-native-observation-qualification-2.log`, all eight native SQLite
integration cases passed in 27.12 seconds; all 1,368 kernel library tests passed
in 57.91 seconds; and all 33 durable security-state integration tests passed in
6.12 seconds. Each group had zero ignored or filtered tests. Strict all-target
Clippy passed for `chio-kernel`, `chio-runtime-core`, `chio-store-sqlite`,
`chio-control-plane` and `xtask`, with warnings denied. All 20 mirror-checker
tests passed; its unrelated filtered integration targets are not extra passes.
The queue then stopped on the intended seven-entry source drift, not a test or
lint failure. Its SHA-256 is
`a01d4a2e9f00fe7b14b3ec6ce31db78b0faa4ed95efebf831564aa936dd7e55b`.

The exact inventories at `/tmp/chio-native-observation-exact.log` passed all
48 native-custody tests in 282.73 seconds, all three observation-constructor
tests, all eight native integration cases and all eight kernel preparation
tests. There were zero ignored tests. Filtered library inventories explicitly
verify their complete selected names and successful execution. The repeated
groups are not added to the complete library/integration results: this slice
has 1,457 distinct selected behavioral passes. The exact log SHA-256 is
`1b1227d100759b2aef000dcee24aff9535585ff7ce550d2f3df0708f6cff65d5`.
Workspace formatting passed. The structural flow contract now validates 43
exact inventories; this slice did not execute the other 39 inventory commands or the full
workspace/release gate.

Four new source references cover the observation type and constructors, SQLite
read transaction, shared flow reader and generation/label decoder boundary.
Existing references cover the portable port, forwarding implementation and
write-error/readback ordering. Review against `PostAdmissionDropGuard` did not
expand its lifecycle abstraction: these references track source drift, not a
proof of native observation integrity, activation or exact SQLite custody.
At `/tmp/chio-native-observation-mirrors.log`, seven of 127 references were
updated. Comparison with the fresh full pre-bless manifest verified hash-only
changes in exactly those seven source files and no remaining placeholders.
All 127 references match; generated coverage and its check report 58 rows and
168 artifacts. Hygiene, public-surface, security CI, exact-runner negative
controls and Apalache structural checks passed. The final code graph has
163,931 nodes, 426,906 edges and 6,991 communities.

The worktree contains 603 changed/untracked files across 11 review slices, with
zero unclassified paths. The source fingerprint, excluding this ledger and
generated coverage, is
`51a484d9461ca715e1ff25477dde81a9b965c4732532af7cef707d173156046c`.
The existing 15 added lockfile lines remain unchanged; lockfile SHA-256 remains
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

This is a native integration prerequisite, not a production native resolver or
serving activation. Dedicated nonce, egress and declassification custody, mixed
native journal recovery, complete authenticated caller/executor start and
delivery, current output-release policy and the remaining protocol, SDK,
sidecar, enterprise, formal, operational and release qualification retain their
full earlier scope. History-dependent integrity reads still require scale and
retention qualification. The physical v29 schema, join-only writer whitelist,
one-join-per-operation rule and final native dispatch refusal are unchanged.
No workflow, operator database, activation or publication was changed. All work
remains local and uncommitted, and the full roadmap goal remains active.

### Native egress custody and SQL mutation scope (selected local qualification)

Admission schema v30 adds actual operation-owned native egress acquisition and
commitment through a separate immutable journal and global projection kind. The
writer requires `CapturePending`, the original native authority/profile, exact
live retained request material, trusted flow identity/generation, same-operation
join and current recovery lease. Canonical argument and complete live-envelope
hashes remain distinct. Acquisition cannot adopt an imported or unowned fence;
commitment references its own acquisition digest and unchanged live envelope.
Neither hash verifies credentials or supplies executable authority.

Join-v1 records, initialization bytes/catalog hashes, sequence and eight-table
monotone policy are preserved. Egress has its own sequence/hash chain and a
fence-only row policy. Recovery applies both native families in global commit
order, checking their independent chains, observation order, row images and
current totals. The combined journal retains the original 65,536-record/64-MiB
bound. Historical readback and exact retries do not renew an expired fence or
restore a stale generation. The v30 migration adds no native activation and
rejects incomplete future catalogs instead of repairing current ones.

The first behavioral run exposed the native catalog reader rejecting admission
v30. The reader now explicitly maps that admission version to the unchanged v29
native catalog. Further review tightened current-owner reads: a missing egress
catalog on v30 denies even when there are no egress events; only a genuine
predecessor may lack that namespace.

The nested-claim regression at
`/tmp/chio-native-egress-claim-cutpoint-before-2.log` failed because acquisition
returned success after a nested SQL trigger changed its operation recovery
claim. Native row capture did not cover that other table. Both native owners now
install a rollback-safe SQL authorizer for the domain command. Only reads and
insert/update actions within the command's closed native table set are allowed.
Unrelated operation/table writes, deletes, schema/pragma changes, attachments,
savepoints and transaction commitment deny; rollback remains available. The
authorizer is removed before journal append and on unwinding, while the capture
guard disables retained callbacks. Both writers recheck the actual operation
lease after domain execution. The original regression passed at
`/tmp/chio-native-egress-claim-cutpoint-after-2.log`; additional join and egress
tests target unrelated operations, which a selected-operation recheck alone
would not protect. The SQLite crate enables rusqlite's `hooks` feature; the
pre-existing lockfile bytes remain unchanged.

An intermediate run passed 64 native-custody tests with zero ignored tests in
457.46 seconds, before the last integrity/SQL-scope additions. Strict all-target
Clippy passed for the kernel, runtime-core, SQLite, control-plane and xtask before
the SQL authorizer addition. Those results are not final-source qualification.
The final exact native inventory passed all 69 tests with zero ignored tests in
529.13 seconds at `/tmp/chio-native-egress-exact-final.log`; the inventory checker
verified every selected name and successful execution. Its SHA-256 is
`9306689d86ff8ffed7f41a326696dbb55d2619b975569090507405edaaa56856`.
These selected tests are included in the complete SQLite library result below,
not additional distinct passes.

The final serial queue passed the complete SQLite library with 1,605 passed,
zero failed and three ignored tests in 2,637.96 seconds. Two substantive checks
remain unqualified: the retention state-machine property linked to #1045 and
the million-receipt scale proof. The third ignored test is the serving-owner
subprocess helper; nested child-process summaries are not extra suite passes.
The log is `/tmp/chio-native-egress-store-lib-final.log`, SHA-256
`cc2375b2f19a85f1b5d2a6ee15e308bb11fbbaa9670a74ed4416af3acd1ec88c`.
All 1,368 kernel library tests passed in 56.59 seconds at
`/tmp/chio-native-egress-kernel-final.log`, SHA-256
`3d2a12bfc7e62072c46334c9ae05a654d52cef597e17a400f9dc9d2f363a9540`.
The eight native-authority integration tests passed in 27.63 seconds and the
33 security-state integration tests passed in 6.38 seconds. Both groups had
zero ignored or filtered tests; their combined log is
`/tmp/chio-native-egress-integration-final.log`, SHA-256
`619319e5876137cbb6879205a4edff7e98fa9347911c91b342ef6f7279acf442`.

Strict all-target Clippy passed for `chio-kernel`, `chio-runtime-core`,
`chio-store-sqlite`, `chio-control-plane` and `xtask`, with warnings denied, at
`/tmp/chio-native-egress-clippy-final.log`. All 20 mirror-checker tests passed at
`/tmp/chio-native-egress-mirror-tests-final.log`; unrelated filtered targets
are not behavioral passes. The queue then stopped only on the intended
12-source formal-reference drift. Ten references are new; the other two cover
the retained-material validator's visibility and the existing native join
writer. Review against `PostAdmissionDropGuard` retained its lifecycle
abstraction, not proof of SQLite custody, migration, mixed journal recovery,
credential verification or native activation.

At `/tmp/chio-native-egress-mirrors-bless-final.log`, 12 of 137 references were
updated. Comparison with the fresh complete pre-bless manifest verified
hash-only changes in exactly those 12 sources and no remaining placeholders.
All 137 references match at `/tmp/chio-native-egress-mirrors-check-final.log`.
Generated coverage and its check report 58 rows and 168 artifacts. Workspace
formatting and `git diff --check` passed. Hygiene, public-surface, security CI,
Apalache structural checks and the exact-runner negative controls passed. The
flow contract validates 43 exact inventories; this slice executed the native
69-test inventory, not all 43 commands or the full workspace/release gate.

The final code graph at `/tmp/chio-native-egress-graph-final.log` has 164,111
nodes, 427,483 edges and 7,010 communities. The worktree contains 623
changed/untracked files across 11 review slices, with zero unclassified paths.
The source fingerprint, excluding this ledger and generated coverage, is
`b8c3189e73e36012717fcb983798d225def39c30d2b1b692b5e7cbe34a069cd9`.
The pre-existing 15 added lockfile lines remain unchanged; lockfile SHA-256 is
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

Kernel-owned portable egress custody and dispatch-ledger coupling, dedicated
nonce, declassification, native resolver/activation, complete authenticated
caller/executor start and delivery, current output-release policy and all
remaining operational/release gates remain open. The final native dispatch
refusal stays intact. No workflow, operator database, publication or serving
activation was changed; all work remains local and uncommitted and the full
roadmap goal remains active.

### Portable native egress custody (selected local qualification)

The kernel's `AdmissionOperationStore` now exposes native egress acquire, commit
and complete-history ports. `NativeSecurityEgressContext` borrows the live
request, original operation, actual lease, selected binding and trusted
context/time. It is command data, not a minted authority or serialized request
envelope. Unsupported backends explicitly reject all three methods.

SQLite resolves the exact selected initialization, then forwards acquire and
commit into the existing operation-owned writers. The preliminary read grants
no authority: each write transaction independently verifies initialization,
original profile/material, live-request hash, context, phase and actual lease.
No alternate native mutation path or schema revision is introduced.

`load_native_security_egress` reads the current operation and both egress phases
in one fenced, anchored transaction. A missing operation is distinct from a
present operation without custody. `NativeSecurityEgressHistoryV1` preserves
the original acquired fence and digest after commitment, together with the
later event and its exact acquisition predecessor. These redacted historical
types contain no raw transient credentials and cannot renew expired fences or
leases. The older latest-event read remains available separately.

All six new real-SQLite tests passed with zero ignored tests in 37.81 seconds at
`/tmp/chio-native-egress-port-initial.log`. They exercise the trait interface,
missing operation versus custody, both phases and current operation readback,
selected binding/material/lease/context substitution, owner rotation, expired
fence and lease history, and missing current catalog rejection. The new kernel
test requires the exact unsupported errors from a backend implementing neither
egress command nor history. The exact inventories now require 75 native custody
tests and nine kernel preparation tests; all 43 inventory contracts validate.

Final selected verification passed all 75 native custody tests with zero ignored
tests in 569.70 seconds at `/tmp/chio-native-egress-port-custody-exact-qualified.log`.
The exact runner verified all selected names and successful execution. The log
SHA-256 is `6eb659ab1d1a681b0fa792dd17bf9fef70207214d86cbb471c6fb684976c8876`.
All nine kernel preparation tests passed in 0.59 seconds at
`/tmp/chio-native-egress-port-kernel-exact-qualified.log`, SHA-256
`704e0396f724c8962c3c3a95dd4b72acfd5444985d1803ad9941819edfe1ea91`.
All 1,369 kernel library tests passed in 57.17 seconds with zero ignored or
filtered tests at `/tmp/chio-native-egress-port-kernel-lib-qualified.log`, SHA-256
`f78595fb0472107ad45a05bde8e5aa5c8b245491f5ed73b9f731ee636803bd13`.
The nine-test inventory is included in that library result, and the initial six
SQLite tests are included in the 75-test inventory; repeated execution is not
counted as additional distinct passes.

The eight native-authority integration tests passed in 28.24 seconds and all
33 security-state integration tests passed in 6.13 seconds, with zero ignored
or filtered tests, at `/tmp/chio-native-egress-port-integration-qualified.log`.
Its SHA-256 is `05fa0ebd69ab640f7f841e5fa607401fa40c9efba1b85357271c25bab0d87663`.
Strict all-target Clippy passed for `chio-kernel`, `chio-runtime-core`,
`chio-store-sqlite`, `chio-control-plane` and `xtask`, with warnings denied.
All 20 mirror-checker tests passed; unrelated filtered targets are not extra
passes. The queue then stopped only on the intended five-source reference drift.

The existing lifecycle abstraction remains unchanged. Three new source
references cover the borrowed input/historical data types, SQLite forwarding
boundary and single-snapshot readback. Existing references cover the store
trait and its SQLite implementation. These anchors do not prove snapshot
integrity, Rust borrowing, exact SQL custody, dispatch coupling or activation.
Five of 140 references were refreshed; comparison with the complete fresh
pre-bless manifest verified hash-only changes in exactly those five sources and
no remaining placeholders. All 140 references match. Generated coverage and its
check report 58 rows and 168 artifacts. Workspace formatting, hygiene,
public-surface, security CI, Apalache structural, exact-runner negative-control
and `git diff --check` gates passed.

The final graph at `/tmp/chio-native-egress-port-graph-final.log` contains
164,159 nodes, 427,658 edges and 6,951 communities. The worktree has 628
changed/untracked files across 11 review slices, with zero unclassified paths.
The source fingerprint, excluding this ledger and generated coverage, is
`241c0c5059cf0c0a3c6b036d30c3f4e6f83a96c9903308bd4911f13c443ca514`.
The existing 15 added lockfile lines remain unchanged; lockfile SHA-256 is
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
The full SQLite library, all 43 flow commands and complete workspace/release
gate were not rerun for this slice. The earlier retention/scale exclusions
remain unqualified, not cleared by the selected custody result.

This supplies the portable store boundary, not the kernel-owned egress
coordinator, fresh post-join production classification or dispatch/credential
coupling. Native dispatch refusal, nonce and declassification boundaries remain
intact. The full prior operational, retention, platform, dependency, protocol,
SDK and release scope remains open. No operator database, workflow, activation
or publication was changed; the roadmap goal remains active.

### Kernel-owned native egress coordinator

The trusted-host `ChioKernel::prepare_native_security_egress` API now binds an
original non-nonce in-kernel `CapturePending` operation to its retained profile,
native selection, stable trusted identity and borrowed live request. It obtains
a fresh post-join observation from the qualified store. Historical join labels
or generation are never treated as a fresh classifier input. Preparation does
not itself classify or authorize the request.

`PreparedNativeSecurityEgress::acquire` and
`AcquiredNativeSecurityEgress::commit` consume their respective opaque handles.
Each derives its own actual recovery lease and rechecks original material,
current configuration, exact operation and the inspected flow state. The
kernel constructs the payload commitment and separate complete live-request
commitment, plus the existing context-bound dispatch commitment. Raw transient
credentials are borrowed, not written to history. This is equality and custody,
not verification or disposition of those credentials.

Both writes require independent history readback, including after a denied or
panicked callback. An error remains an error even if a write committed. The
readback must preserve original acquisition, event digests and the commitment's
exact predecessor. Later state changes, expired deadlines and changed history
deny success. Store panics are contained inside the mutation sequencer so they
cannot prevent later recovery reads by poisoning that lock. Dropping either
handle grants no compensation or execution authority.

The real SQLite integration exposed an overstrict timestamp comparison in the
new coordinator: SQLite samples time inside its read transaction, which can be
later than the kernel's pre-read sample. The fixed coordinator requires the
observation timestamp to lie within the actual before/after kernel read
interval. No skew allowance or clock tolerance was added. Dedicated negative
tests reject stale and future timestamps; the actual admission/budget/SQLite
coordinator regression then passed in 8.32 seconds. After physical acquisition
and commitment, native dispatch still denies, connector invocations stay zero,
quota returns to zero and the anchored custody history remains readable.

The `admission-test-support` observer exercises this real pre-dispatch boundary
without bypassing its final refusal. No observer field or call site exists
without the test-support feature. The exact flow gate now includes eight
coordinator tests and nine native-authority integration tests, with 44 total
structural inventory contracts. Final selected qualification passed:

- All 1,377 kernel library tests passed in 55.36 seconds, with zero ignored or
  filtered tests, at `/tmp/chio-native-egress-coordinator-kernel-qualified.log`.
  SHA-256: `bd66b7f05d12cfce9dc880de03e992403f602d74f123d8e14fad3843d1470833`.
- All eight exact coordinator tests passed in 0.49 seconds at
  `/tmp/chio-native-egress-coordinator-exact-0.log`, SHA-256
  `3390a29688a3eec45c63460452dca564450e58098da9388b8d103a06795bdd89`.
  The nine preparation and 22 original-selection tests also passed their exact
  inventories. These filtered selections are included in the full kernel total,
  not additional distinct tests.
- All nine exact native-authority SQLite integration tests passed in 33.73
  seconds, with zero ignored or filtered tests, at
  `/tmp/chio-native-egress-coordinator-sqlite-qualified.log`. SHA-256:
  `2b98f3aacfcdd6fcd4adfa112cbc1bc236d078b6a629dfe29f5af8094c1f95e4`.
  Strict Clippy first rejected an `expect` in the new test observer. The observer
  now reports a poisoned result lock through the test reader, without a lint
  exemption; this integration inventory passed again after that cleanup.
- Strict all-target Clippy passed for `chio-kernel`, `chio-runtime-core`,
  `chio-store-sqlite`, `chio-control-plane` and `xtask`. The non-test kernel
  library build passed separately in 24.22 seconds. All 22 selected mirror and
  CLI checker tests passed; unrelated filtered integration targets add no passes.

One new lifecycle abstraction anchor records the custody coordinator. It does
not prove classification, credential verification, SQLite isolation, Rust
lifetimes or complete native dispatch activation. Exactly three of 141
references changed: the test-only pre-dispatch checkpoint, shared panic wrapper
visibility and new coordinator. Complete before/after manifest comparison
verified hash-only refreshes in exactly those sources, with no placeholders.
All 141 references match. Coverage generation and checking report 58 rows and
168 artifacts; workspace formatting, hygiene, public-surface, security CI
negative controls, exact runner/verifier self-tests, all 44 flow inventory
contracts, Apalache structural checks and `git diff --check` passed. This slice
did not rerun the full SQLite library, all 44 flow commands, model checking or
the complete workspace/release gate.

The worktree contains 632 changed/untracked paths across 11 review slices, with
zero unclassified paths. The source fingerprint excluding this ledger and
generated coverage is
`d47bf42fda82a6945abab147a043fb3d21eb342b4b22544d048478c5dfd84e03`.
The pre-existing 15 added lockfile lines remain unchanged; lockfile SHA-256 is
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
The final AST graph refresh completed at
`/tmp/chio-native-egress-coordinator-graph-qualified.log`: 164,250 nodes,
427,947 edges and 7,014 communities. The roadmap goal remains active.

This is a custody coordinator, not native lifecycle activation. Production
classification, dispatch-ledger/credential coupling, native nonce,
declassification, outcome/recovery integration and explicit activation remain
required. The complete prior operational, retention/scale, platform, dependency,
protocol, SDK, pilot and release scope is unchanged. No operator database,
workflow pin, publication or hosted activation was changed.

### Native post-join policy and kernel-bound custody

`NativeFlowResolver` now evaluates the canonical arguments of a kernel-prepared
live request against admitted manifest/bridge metadata and an authenticated
classifier result. A shared private `FlowPolicyView` contains this read-only
logic for both legacy and native paths. The native resolver has no flow-state
backend and rejects legacy receipt/declassification evidence configuration.
Its selected binding must match the original kernel handle before any policy
callback. Native declassification is explicitly unsupported, not routed into
legacy one-shot consumption.

The kernel handle exposes its original borrowed request and operation identifier
plus nonmutating current-custody validation. The resulting affine
`PreparedNativeFlowDispatch` borrows both resolver and kernel custody until its
consuming `commit_custody` call. It rechecks the actual kernel operation,
observation and clock; callback panics, clock regressions/future samples, exact
expiry and canonical-time overflow deny. It returns historical policy and
optional egress data, never an execution permit or credential disposition.
Non-egress decisions do not manufacture an egress acquisition or commitment.

The computed complete input taint must already be covered by every native
principal, lineage and session label. Merely checking the effective session
would miss an inherited restriction absent from the lineage record. Classifier
drift, a stronger operator floor or incomplete propagation denies without
silently dropping a required taint write or attempting a second admission join.
The actual SQLite tests retain the original monotone join, independently read
back both egress events when applicable, verify zero connector invocations and
released invocation quota, and keep the unconditional native dispatch refusal.

The initial 14-test run exposed three fixture mistakes, not a permission change:
the new manifest helper had reversed output-label and input-clearance arguments.
After correcting the helper and adding the remaining negative cases, all 70
adapter tests passed in 90.91 seconds with zero ignored tests (949 unrelated
tests filtered). This includes the 19 new native-policy tests and the existing
legacy flow/declassification tests. Strict all-target Clippy passed for
`chio-kernel`, `chio-runtime-core`, `chio-store-sqlite`, `chio-control-plane`
and `xtask` in 2m 04s. The exact flow gate now contains 46 structural inventory
contracts, including 18 real-authority policy cases and one time-boundary test.

Two new lifecycle abstraction anchors cover the shared policy view and native
resolver. Complete before/after manifest comparison verified hash-only changes
in exactly four expected sources, with no placeholders. All 143 references
match, coverage generation/checking reports 58 rows and 168 artifacts, and all
22 selected mirror/CLI tests passed. These anchors do not prove classifier
correctness, manifest authenticity, Rust lifetimes, SQLite isolation or full
native activation.

At the post-join checkpoint, the production before-budget classifier hook was
still required (implemented by the subsequent checkpoint below). An absent epoch
does not establish public inherited lineage, and the original single input join
must propagate the complete source into all three labels. Dispatch-ledger and
credential coupling, native nonce/declassification, owned outcomes/recovery,
caller start/return/release integration and explicit activation also remain
required. The complete operational, retention/scale, platform, dependency,
protocol, SDK, pilot and release requirements above are unchanged. No operator
database, workflow pin, hosted activation, commit, push or publication changed.

Final selected qualification for this slice:

- All 1,019 control-plane library tests passed in 1,267.80 seconds, with no
  ignored or filtered tests, at `/tmp/chio-native-flow-policy-control-plane.log`.
  SHA-256: `002b2fb9ae6025d6b792aa70336926d92b12a1ca837526301d94569733693866`.
- All 1,377 kernel library tests passed in 57.51 seconds, with no ignored or
  filtered tests, at `/tmp/chio-native-flow-policy-kernel.log`. SHA-256:
  `29c3eabfdcb111922eefb9f43d7f340faf2154e4afcb3cde22ded3b1e0cb2429`.
- Final fixture review moved its temporary-directory field after the kernel
  and authority fields so live stores are dropped before their files. This
  test-only fix changed no production code. The full control-plane run above
  predates that teardown correction; it was not repeated in full afterward.
  All 18 affected native-policy tests passed again on final source in 86.31
  seconds, with no ignored tests, at
  `/tmp/chio-native-flow-policy-exact-final-0.log`. SHA-256:
  `2de8620ac5be70e827231f78d147d733fed1b043af04ca27d45cdd71eb8f2c60`.
  The separate exact clock-boundary test also passed on final source. The 13
  legacy prepared-dispatch and eight kernel coordinator exact inventories passed
  as well; these subsets are not additional unique tests beyond the library runs.
- Final strict all-target Clippy for the five selected packages passed in 49.53
  seconds at `/tmp/chio-native-flow-policy-clippy-final.log`. SHA-256:
  `07fa099b1812c2d4a2fb6e63a3de4edab1f2526092859fad3b423577259ee217`.
  The non-test control-plane library check passed separately in 26.00 seconds.
  Final formatting, all 143 source/proof references, hygiene, public-surface,
  all 46 flow inventory contracts and `git diff --check` passed. Security CI
  negative controls, exact-runner/verifier self-tests and Apalache structural
  checks also passed. This did not rerun the full SQLite library, all 46 flow
  commands, model checking or the complete workspace/release gate.

The final AST graph refresh, including the teardown fix, completed at
`/tmp/chio-native-flow-policy-graph-final.log`: 164,358 nodes, 428,245 edges and
7,014 communities. Its SHA-256 is
`b7aee5f508e762c2036cabcdafb8b876487f00d4eac8585bba8146dabe0f933b`.
The worktree contains 637 changed/untracked paths across 11 review slices, with
zero unclassified paths. The source fingerprint excluding this ledger and
generated coverage is
`27affa3b2890e0dc8ad4f1550b599978568f2cda23eafd0edcdcb83da9f088d2`.
The pre-existing 15 added lockfile lines remain unchanged; lockfile SHA-256 is
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
The full roadmap goal remains active.

### Native classified-input full-source join

The production `NativeFlowResolver` now implements `SecurityPreDispatchHook`.
Before budget capture, it validates admitted manifest/bridge metadata and
classifies the original canonical arguments with the same classifier identity,
version, tenant, request and payload-digest checks used by post-join policy.
It combines classification
with the operator floor, then supplies only that label to the kernel's
`NativeSecurityFlowJoinAuthority::join_input`. Unsupported native
declassification rejects before classification or mutation. No legacy state,
receipt or declassification backend is installed, and legacy dispatch rejects.

The kernel derives the operation, complete flow identity and domain-separated
input transition. Raw and input calls share sticky failure and single-attempt
custody. The physical writer resolves every actual principal, global lineage
and session row under the existing fenced write transaction, before enabling
the affine native writer. Absence of an exact epoch does not erase inherited
lineage or an existing principal epoch under another lineage. The complete
source is propagated into all three labels in one captured mutation, preserving
the actual recovery lease, generation checks, SQL allowlist, row/history bounds,
commit chain and cutpoints. No writer is created by source inspection.

The distinct original `NativeSecurityInputJoinRequestV1` and resolved join are
retained in the bounded internal `chio.native-security-flow-join.v2` event.
Raw v1 events preserve their canonical shape and independent-label semantics.
This adds no SQL catalog migration and rewrites no old history. Raw/input
cross-family retries deny even when the resolved command and transition prefix
match. Unknown versions, v1 with input, v2 without input and noncanonical data
fail closed. Input v2 history also requires the original native binding and
selected authority profile during readback and recovery, not only when written.
Existing v1 readers reject the new input field rather than silently
reinterpreting it. Historical retries return the original result after later
label changes; they are not fresh observations or execution authority.

The input acknowledgement must exactly match an independent fenced read of
original intent, current operation, selected binding, resolved command, result
and mutation digest. Readback is attempted even after write denial or panic;
lost acknowledgements remain errors when a monotone write committed. Post-join
policy still reclassifies fresh state and rejects stronger unrecorded taint
without another join. Non-egress policy acquires no egress fence.

Local qualification completed with Rust 1.94.1, locked/offline dependencies,
`umask 022`, disabled incremental compilation and serial Cargo/test execution.
The final frozen-source checks passed:

| Check | Result | Evidence log under `/tmp/` |
|---|---|---|
| Complete kernel library | 1,383 passed, 0 filtered, 58.02 seconds | `chio-native-input-join-kernel-frozen.log` |
| All control-plane security adapters | 81 passed, 949 filtered, 161.82 seconds | `chio-native-input-join-adapters-frozen.log` |
| SQLite classified-input mutation cases | 7 passed, 1,614 filtered, 65.19 seconds | `chio-native-input-join-store-frozen.log` |
| Independent process-abort/takeover parent | 1 passed, 1,620 filtered, 56.00 seconds; raw and input families at cutpoints 7 through 11 | `chio-native-input-join-process-frozen.log` |
| Non-test control-plane library compilation | Passed | `chio-native-input-join-production-frozen.log` |
| Strict all-target Clippy for kernel, runtime-core, SQLite, control-plane and xtask | Passed with warnings denied | `chio-native-input-join-clippy-frozen.log` |

Every test result above has zero failed, ignored or measured tests. The frozen
evidence-log SHA-256 values, in table order, are:

- Kernel: `49b4b04f481ad6a1402f913b4784462067773ae785c494b06ad7d913be56d386`.
- Adapters: `8c53b397d0a7c7a611609cb63e11a920b4514571726a7351ef7916f578555fa7`.
- SQLite input: `b57e9105d5c951b6143cb78c247e9a300908027dd4a5a7473eeb7f828c709de2`.
- Process recovery: `f2253e61d57b8858efe54f1f9203db75dd75399a25e820653182bd5831f53cb4`.
- Production compilation: `f989ce0f1ce0f4568bfbf557375c3e79b5df0193485bf6040a597f06f8c7335b`.
- Clippy: `b3ee2182e31fd4219afa184eb08b30be05ad1194b315edc0879e9378425427b3`.

The earlier seven exact inventories also passed: 82 native SQLite cases,
29 native control-plane cases, 11 kernel preparation cases, four portable input
intent cases, nine real-store native-authority integration cases, 13 legacy
prepared-flow cases and eight kernel egress cases. Their logs are
`/tmp/chio-native-input-join-exact-0.log` through
`/tmp/chio-native-input-join-exact-6.log`. The 82-case SQLite run predates the
final stricter v2 history-custody validation. The final seven input cases and
expanded process-abort parent above were rerun after that change. This is not a
claim that the full SQLite library or workspace suite ran on the frozen source.

Formal drift checks match all 148 source anchors, including five new input-join
anchors. Full before/after manifest comparison confirmed that blessing changed
only hashes for the 12 expected source entries. Generated proof coverage matches
58 rows and 168 artifacts; 22 formal-mirror/CLI tests passed with zero ignored.
The logs are `/tmp/chio-native-input-join-mirrors.log`,
`/tmp/chio-native-input-join-coverage.log` and
`/tmp/chio-native-input-join-mirror-tests.log`. The first two log SHA-256 values
are `cc7b959a0167db69308a999eef73bd0fd5521527ed8e23c289194afead2ca56c`
and `2666f073a716240d5b308549d2deb671b1dded52ee44545e76a682979dd67a4b`.
These are source-drift and coverage checks, not a new model-checking result.

Rust hygiene, public-surface policy, all 47 exact-inventory structural contracts,
Apalache wrapper structure, security-CI negative controls, exact-inventory
verifier/runner self-tests, workspace formatting and `git diff --check` passed.
The 47 structural contracts do not imply execution of all 47 flow commands.
No workspace-wide, release-gate or hosted qualification is claimed here.

The final AST-only graph refresh completed with 164,517 nodes, 428,820 edges and
7,036 communities. Its log is `/tmp/chio-native-input-join-graph-final.log`,
SHA-256 `f9bad60fb499a916f331135d47bdca33947785d637c30f481eaa2ff814d2e8db`.
The worktree remains on `security/launch-integration` at
`8b9f9243905dfa61acac82d83438684940777fe3`, with 645 changed/untracked paths
across 11 review slices and zero unclassified paths. The frozen source
fingerprint excluding this ledger and generated coverage is
`1d60170f823b6a2d332e67979fcd11b757e1f2534303756fd9ee3bb5d3699ee3`.
The pre-existing 15 added lockfile lines remain unchanged; lockfile SHA-256 is
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

The full roadmap remains active, and native dispatch remains disabled.
Dispatch-ledger and credential dispositions, native nonce and
declassification/use/outcome/recovery, authenticated caller start and owned
delivery, current output release and explicit activation remain required.
All operational, retention/scale, platform, dependency, protocol, SDK, pilot and
release requirements above remain in scope. No operator database, workflow pin,
hosted activation, commit, push, merge or publication is authorized by this work.

### Security-denial credential ordering and irreversible nonce history

Review of the next native dispatch/credential handoff reproduced a live ordinary
and nested dispatch bug: `retain_if_dropped` ran before the security hook, so a
definite security rejection could consume a non-reservable legacy nonce and
retain approval custody without a tool invocation. Two regression cases failed
on the original code because the legacy nonce store received one consumption
instead of zero (`/tmp/chio-security-credential-rejection-red.log`).

Security acceptance now precedes the dispatch retention boundary in both paths.
A shared rejection handler resolves reversible credentials before signing the
denial and uses the actual retained disposition after prior payment. Cleanup
errors, ownership loss and panics report unknown retention. No credential
presence is inferred from payment authorization alone. Security acceptance
followed by credential-retention failure explicitly records `DispatchFailed`;
an unconfirmed outcome recorder returns recovery-required rather than a normal
signed denial. Existing unknown dispatch-commit handling still retains custody.

The legacy nonce now has explicit absent, pending, retained, rejected and unknown
states. The first attempt consumes its pending intent before the callback;
rejection or lost acknowledgement remains a sticky failure on repeat, commit and
Drop without another store call. Reversible cleanup cannot erase confirmed
consumption or assert rollback of a marker this attempt does not own. This is
in-memory lifecycle state, not a new durable credential artifact or database
migration.

Regression matrices cover ordinary/nested rejection, lifecycle/commit panics,
wrong security outcome ownership, the complete reversible DPoP/nonce/approval
set, failed approval rollback, exact retry after confirmed cleanup, payment with
and without approval, sticky nonce failures and failed outcome recording. The
flow gate now has exact inventories for these security and payment boundaries;
its success message follows the last required inventory, with a negative control
for premature or duplicated success.

Local qualification passed with Rust 1.94.1, locked/offline dependencies,
`umask 022`, disabled incremental compilation and serial Cargo/test execution.
Seven new regression tests expand the prior kernel inventory from 1,383 to
1,390. The final rerun followed source freeze and manifest regeneration:

| Check | Result | Evidence log under `/tmp/` |
|---|---|---|
| Complete kernel library | 1,390 passed, 0 filtered, 58.54 seconds | `chio-security-credential-kernel-frozen.log` |
| Exact security callback and credential boundary inventory | 8 passed, 1,382 filtered, 0.86 seconds | `chio-security-credential-exact-0.log` |
| Exact payment/dispatch rejection inventory | 8 passed, 1,382 filtered, 0.61 seconds | `chio-security-credential-exact-1.log` |
| Exact real-SQLite native authority integration | 9 passed, 0 filtered, 36.10 seconds | `chio-security-credential-exact-2.log` |
| All control-plane security adapters | 81 passed, 949 filtered, 155.34 seconds | `chio-security-credential-adapters-final.log` |
| Formal-mirror and CLI tests | 22 passed, 146 filtered, 0.08 seconds | `chio-security-credential-mirror-tests.log` |

All executed tests above have zero failed, ignored or measured cases. The two
eight-test exact inventories overlap the complete kernel library and are not
additional unique tests. The two xtask integration targets selected no tests under the mirror
filter and add no behavioral evidence. The final kernel log SHA-256 is
`cfacd9bd9c9268552a1cbdd94fa683c6a1487c8f64da17ee34e5580e0f06dbde`;
the adapter log SHA-256 is
`94ac4c28bc9a520e3815cf275e2af73eb4153b2591529fb6c0c4ecae8dec6306`.
The original failing calibration log SHA-256 is
`9d33f56608a5af310cb2412436b79b8daca57aa525c379c48b853ca5ce9ba02e`.

The non-test control-plane library compiled successfully in 1 minute 15 seconds.
Strict all-target Clippy for kernel, runtime-core, SQLite, control-plane and
xtask passed in 2 minutes 6 seconds with warnings denied. Their logs are
`/tmp/chio-security-credential-production-final.log` (SHA-256
`82a5f537cf0abc9167e5707ab65b3d81a6c990a4d02db1460099095444fb0476`)
and `/tmp/chio-security-credential-clippy-final.log` (SHA-256
`9a17ba499c42fcf4b75a6d92dd5a2e19b786b494a57fbe3b349535c62f64c985`).
Workspace formatting and `git diff --check` passed again after the final kernel
run. No timeout, lint waiver or ignored-test allowance was added.

Formal drift checks match all 149 anchors. One new legacy-nonce source anchor
and two extended symbol selections cover the explicit state and shared cleanup.
Full before/after manifest comparison confirmed that blessing changed only the
nine expected hash entries, preserving every non-hash field. Coverage generation
and checking match 58 rows and 168 artifacts. These checks do not claim new model
checking, refinement or transitive proof coverage. Rust hygiene, public-surface
policy, all 49 flow-inventory structural contracts, Apalache wrapper structure,
the security-CI structural contract and exact-inventory verifier/runner self-tests
passed. Only the three exact flow inventories listed above were executed here,
not all 49 flow commands. Full workspace, full SQLite library, composed durable
credential crash recovery, platform enforcement and release qualification are
not established by this checkpoint.

The final AST-only graph refresh completed with 164,560 nodes, 428,891 edges and
7,043 communities. Its log is `/tmp/chio-security-credential-graph-final.log`,
SHA-256 `8287028a10246d90af92bc4f7ec5ab08faa3130a162f9812eaa5807bc19b4e6a`.
The worktree remains on `security/launch-integration` at
`8b9f9243905dfa61acac82d83438684940777fe3`, with 648 changed/untracked paths
across 11 review slices and zero unclassified paths. The source fingerprint
excluding this ledger and generated coverage is
`e5c903528fe88b98c886b695ed999b606e4dcb1a0ed7d9c07539042b4b2caf0f`.
The pre-existing 15 added lockfile lines remain unchanged; lockfile SHA-256 is
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

The full roadmap remains active. Native dispatch-ledger and credential coupling,
native nonce/declassification/use/outcome/recovery and activation, complete caller
snapshot/start/delivery/release, and all operational, platform, retention/scale,
dependency, protocol/SDK, pilot and release requirements remain in scope. This
checkpoint does not authorize activation, operator database changes, publication,
commits, pushes, merges or hosted jobs.

### Native capture refusal and physical hold ownership

Review of dispatch-ledger integration reproduced three lower-level bypasses of
the kernel's unsupported-native gate. The real kernel created retained v4 native
admission with a physical budget hold, yet direct combined capture, split budget
capture and generic `DispatchCommitted` advancement succeeded without a native
dispatch ledger. All three regression cases failed for that intended reason in
`/tmp/chio-native-capture-red.log`. This is an in-process store-boundary failure,
not evidence that an untrusted agent can directly access those host APIs.

SQLite now checks original native selection inside the capture transaction and
before generic or participant-bound advancement can persist a dispatch commit.
Neither a monotone join nor an acquired and committed egress fence grants an
exception. The real-kernel regressions exercise each route both before and after
egress commitment, require unchanged operation/global/budget journals, and verify
zero connector calls and successful pre-dispatch quota reversal after denial.

Capture also resolves the physical hold's original owner before event replay or
mutation. Matching a capability and copying a hold attachment cannot transfer
that hold to another operation. A separate production-store regression rejects
substitution before the owner's capture and during exact replay, while the
actual owner still captures once and replays without another mutation. The
existing nonce split-capture refusal is preserved in the shared owner check.

The shared budget API also supports opaque budget-only operation references.
These are not automatically admission identities, even when they look like a
64-character digest. Membership checks preserve that standalone lifecycle while
denying a missing row for a committed admission. Opaque references are not
allocated merely to classify them; actual admission IDs are byte-bounded in
SQLite before decoding. A rollback-only missing-row fault test exercises the
inner ownership check without relying on the outer anchor verifier.

Two existing egress fixtures depended on the now-forbidden generic native
dispatch transition. They now assert that refusal and leave capture custody
through physical hold reversal and a real terminal projection. The fixtures
first prove a live hold cannot be compensated by a test envelope's release claim
alone. They retain stale-command rejection and current-operation readback with
unchanged acquisition/commitment history before and after reopen.

This checkpoint does not implement or activate the native dispatch ledger.
The next ledger implementation must bind original admission/profile, the full
live request, grant, verified policy inputs and decision, fresh observation,
join/egress predecessors and actual credential dispositions at this physical
boundary. Historical DTOs or a digest attached through generic CAS cannot replace
those checks. Nonce/declassification/use/outcome/recovery, caller start/delivery,
current release policy, explicit activation and all other roadmap requirements
above remain required. No operator database migration, commit, push, merge,
workflow repin, hosted job or publication is part of this checkpoint.

The local candidate uses Rust 1.94.1, locked offline dependencies, `umask 022`,
disabled incremental compilation and serial tests. Cargo processes do not
overlap. No timeout, stack, ignore, lint or assertion relaxation qualifies this
change. The initial broad library run exposed a preflight diagnostic ordering
regression; preflight rejection now retains its original precedence. A later
completed diagnostic build had 1,611 passed, eight failed and three existing
ignored tests. Its six budget-only reference failures and two obsolete native
egress fixture transitions were corrected and all eight passed focused reruns.
Neither diagnostic build is final qualification.

Focused qualification on the corrected source:

- Exact native admission integration inventory: 12 passed, zero ignored and zero
  filtered, including all three new capture routes in both join-only and
  committed-egress scenarios.
- Exact physical hold ownership inventory: three passed, zero ignored and 1,621
  filtered. The complete budget atomicity group separately passed all six tests.
- Both changed egress phase/history fixtures passed; all 17 composite lifecycle
  and six joint-owner compatibility cases passed.
- Strict all-target Clippy passed for `chio-store-sqlite`, `chio-kernel`,
  `chio-control-plane` and `xtask`, with warnings treated as errors.
- All 152 formal source-drift anchors match. Three new anchors and one extended
  existing anchor account for all four blessed entries. Full manifest comparison
  preserves root metadata and every other original entry; symbol inventories
  match their digest lists, with no duplicate model/source pair. All 22 mirror
  tooling tests passed. Generated proof coverage matches 58 rows and 168
  artifacts. These are drift checks, not new model-checking or refinement proofs.
- Public-surface, hygiene, security-CI contract, Apalache-wrapper and exact test
  runner/verifier self-tests passed. The flow gate's structural test validates
  all 50 exact inventories; this does not claim execution of all 50 gate commands.
- The final AST-only graph refresh completed with 164,591 nodes, 428,936 edges
  and 6,994 communities. No LLM extraction was used. Graph reachability is a
  navigation aid, not proof of a security invariant.

The exact integration, ownership, Clippy and final graph logs are retained at
`/tmp/chio-native-capture-integration-exact-final.log`,
`/tmp/chio-native-capture-owner-exact-final.log`,
`/tmp/chio-native-capture-clippy-final.log` and
`/tmp/chio-native-capture-graph-frozen.log`. Their SHA-256 values, in that order,
are:

```text
54d86809a4eb1d77a8ab304f391de486a947fe0acb8e1c226de008fec230fa8c
1d8b1d903ade2f472aeca7d80535483a4220c5e6bb999d13da71172fdde2e622
f674c23a37906d77299546c449fff631a2586e486a07820077da38341cd7083e
2fc0d541654377f97e1c6236f7298a511ccfd60b2dc5ac8e34ca122587ba7204
```

Final qualification on the same frozen source completed successfully:

- Full `chio-store-sqlite` library: 1,621 passed, zero failed, three existing
  ignored and zero filtered, in 2,820.11 seconds. All eight failures from the
  earlier diagnostic build passed in this complete rerun. The subprocess helper
  also ran once under its parent test; its separate one-test summary is not added
  to the library inventory.
- Control-plane security adapters: 81 passed, zero ignored and 949 filtered.
  The non-test `chio-control-plane` production check also passed.
- Final formatting, whitespace diff, file hygiene and public-surface checks
  passed. The post-test content fingerprint is unchanged from the pre-test
  fingerprint below. No Cargo, Rust compiler or graph refresh remained running
  when the final results were recorded.

The three ignored library entries predate this checkpoint:
`receipt_store::tests::retention::state_machine::prop_retention_preserves_append_invariant`
is tracked by issue #1045;
`receipt_store::tests::scale_proof::append_scale_proof_is_batch_bounded_across_history_sizes`
is the separate release-only proof that seeds up to one million receipts; and
`serving_owner::tests::serving_owner_child_process` is a subprocess helper invoked
by parent tests. The retention and scale requirements remain open, not waived.

The complete SQLite, control-plane adapter and production-check logs are
`/tmp/chio-native-capture-sqlite-frozen.log`,
`/tmp/chio-native-capture-cp-adapters-final.log` and
`/tmp/chio-native-capture-cp-check-final.log`. Their SHA-256 values, in that order,
are:

```text
5c72ae7d5526918f287bf2e0e2e5173928bef5f4fcea4c2d6130e2005b34b3b1
2a0935d3d9e9521e17b44896dc7ba077c740aaa9fb609b5b8360ff98889940e1
f66037d96486ee97ffaf876d7c06631b2ed5ab3b33669d3577470923132e979c
```

The local integration candidate has 653 changed/untracked paths classified
across all 11 review slices, with zero unclassified paths. This classification
does not assert a fresh review of every inherited change. The content fingerprint,
excluding this ledger and generated proof coverage, is
`e46c973e916b5d04b8a806a06df639c00d6b65487d5f6ada000e1b59123016a9`.
HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`. The pre-existing 15 added
lockfile lines remain unchanged, with SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
No full-workspace, hosted-CI, platform, pilot or release qualification is claimed.

### Native dispatch policy evidence

The next dispatch-ledger integration step found that policy resolution discarded
the exact classifier output and effective policy inputs after computing its
decision. Native preparation now produces
`chio.native-flow-dispatch-policy.v1` from that same evaluation. The verified
classification owns its original bounded result, with immutable evidence access;
its debug output does not print finding locations. Policy resolution returns the
request, verified classification and admitted metadata together, so evidence
construction cannot silently classify a second time or resolve a different tool.

The canonical policy record binds operation/version, retained original-request
digest, full live-request digest, kernel policy identity, native selection,
observed state/generation/time, exact classification findings and category
bindings, operator floor, admitted policy and bridge metadata, manifest
attestation, decision and deadline. The manifest reference consists of its
already admitted canonical body digest, signer and signature. It does not impose
the policy-record limit on a valid larger manifest. Arguments and reusable live
credentials are absent from the record.
Classifier field paths and labels can still reveal sensitive metadata, so the
record is not an unredacted logging payload. Its debug representation exposes
only the encoded length.

The record's 256-KiB limit is enforced while serializing, before constructing a
parsed value or canonical copy. Oversized policy material denies before egress
acquisition. The affine prepared policy carries the same bytes and digest into
successful historical custody. Existing current-operation and clock checks
still run after preparation and at commitment; recorded time never renews a
lease or authorizes historical reuse. Test fixtures independently compare the
retained-request digest with actual SQLite history and preserve zero connector
calls, pre-dispatch compensation and the final native refusal.

This is implemented policy input for the native dispatch ledger, not an attached
SQLite ledger, credential disposition or dispatch activation. The next physical
transaction still must bind the exact selected grant, original participant
profile, actual runtime/approval/DPoP ownership, live request, join/egress
predecessors and current lease/time to budget capture. Generic CAS and split
capture remain forbidden for native dispatch. Native nonce/declassification,
use/outcome/recovery, caller snapshot/start/delivery/current release, complete
participant profiles and all prior operational/platform/dependency/protocol/SDK,
retention/scale, pilot and release requirements remain open and in scope.

Focused qualification completed with Rust 1.94.1, locked/offline dependencies,
`umask 022`, disabled core dumps and incremental compilation, and one test
thread. Cargo commands ran serially. On the final Rust source:

- The exact flow inventory passed all 46 tests, with zero failed, ignored or
  filtered. This includes the new exact-classification evidence test and three
  existing prepared-flow tests absent from the previous declared inventory.
- The exact native policy inventory passed all 33 tests, with zero failed or
  ignored and 1,001 filtered, in 184.84 seconds. All four new evidence cases
  passed, including a valid 300-KB manifest producing a record below 16 KiB and
  oversized policy material denying before any egress custody.
- The exact kernel-owned egress inventory passed all eight tests, with zero
  failed or ignored and 1,382 filtered. All 85 control-plane security-adapter
  tests separately passed, with zero failed or ignored and 949 filtered, in
  187.90 seconds. The 33 native policy cases are included in those 85, not
  additional distinct tests. The earlier 32-case policy log is diagnostic only
  and is superseded by the final inventory and adapter runs.
- `chio-flow` passed its no-default-features `wasm32-unknown-unknown` check.
  Strict all-target Clippy passed for `chio-flow`, `chio-kernel`,
  `chio-control-plane`, `chio-store-sqlite` and `xtask`, with warnings denied.
  The separate production `chio-control-plane` check also passed.
- All 154 formal source-drift entries match. Two new anchors and three extended
  anchors account for exactly five refreshed entries. Comparison preserves all
  152 original entries, all root metadata and every non-hash field in the
  reviewed pre-bless manifest. All 22 mirror-tooling tests passed, with zero
  failed or ignored and 146 filtered. Generated proof coverage matches 58 rows
  and 168 artifacts. These are drift and tooling checks, not new model-checking
  runs or refinement proofs.
- Workspace formatting, explicit formatting checks for included test sources,
  whitespace diff, file hygiene and public-surface checks passed. The flow-gate
  self-test passed all 50 declared inventories; it does not execute all 50
  behavioral gate commands. No tests, assertions or lint gates were waived.
- The final AST-only graph refresh completed with 164,629 nodes, 429,035 edges
  and 7,014 communities. Graph navigation does not prove a security invariant.

The exact flow, final native policy, final kernel egress and full adapter logs
are `/tmp/chio-native-ledger-flow-exact.log`,
`/tmp/chio-native-ledger-policy-exact-frozen.log`,
`/tmp/chio-native-ledger-egress-exact-frozen.log` and
`/tmp/chio-native-ledger-adapters-frozen.log`. Their SHA-256 values, in that order,
are:

```text
7e55227a5d4747e0a0f086ba9440dd3e464723fccea907a85444f31c40a9c7a3
c866ffbc85155eb4cd6f9bf1fa12d89dad0b637fa274ce1e4488bd49a39a04f4
b5aad8cae79a2d6c0365c50d80e158bbd340196d5472c4dce7586db9ac97bd8a
29d68a0db48a752bc12aa9bb7e5f33ce84e49fca703d99ff193c886d7fb14bc6
```

The final Clippy, production check, mirror check and mirror-test logs are
`/tmp/chio-native-ledger-clippy-frozen.log`,
`/tmp/chio-native-ledger-cp-check-frozen.log`,
`/tmp/chio-native-ledger-mirrors-check.log` and
`/tmp/chio-native-ledger-mirror-tests.log`. Their SHA-256 values, in that order,
are:

```text
beaa2ea0c0bfab6d1ca4410509dd665e52129133784afe56ee9ff7524c6080fa
c5d5b918f7d330cd7ca3510439075d2ac099e7840ffea5e9886614750793d2b9
6baea78e4cd2893cfea8c886acf12f2a582ebce3fc825a7867af8101cac45da5
662028acd24d8bd240a77798f762ff3f1ee512dedd19c9234fec2690e815d8ed
```

The candidate has 656 changed/untracked paths across all 11 review slices, with
zero unclassified paths. Classification is not a fresh audit of every inherited
change. The final content fingerprint, excluding this ledger and generated
proof coverage, is
`cf5af97ff6b4a06be70683db5579bfaa4f331433c5dc6229171a161039ff176b`.
HEAD remains `8b9f9243905dfa61acac82d83438684940777fe3`; the pre-existing 15
added lockfile lines are unchanged, with SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
The preceding full SQLite run remains historical evidence, not a full-suite
rerun for this checkpoint. Full-workspace, hosted-CI, platform, pilot and release
qualification are not claimed.

All work remains local and uncommitted in `/tmp/arc-security-launch`. This
checkpoint does not authorize operator database changes, workflow repins,
commits, pushes, merges, hosted jobs, publication or native activation.

### Native dispatch preparation journal

The preceding policy-evidence checkpoint now feeds an actual immutable SQLite
preparation journal, `chio.native-dispatch-preparation-ledger.v1`. The kernel's
consume-once local and egress handles retain the same policy bytes through the
control-plane producer. The writer binds the exact original operation/version,
qualified historical recovery lease, native initialization and context, selected
grant, full live-request digest, policy observation and deadline, join/egress
predecessors, and actual runtime/approval/DPoP claim references and intents. No
classifier rerun or replacement policy lookup supplies that record.

Retention verifies the current physical authorized hold and selected grant,
fresh policy state, participant liveness and operation lease. The immutable row
and its named global authority projection commit in one transaction. Independent
readback checks canonical bytes, bounded length, digest, original command and
two matching readbacks. Lost acknowledgements, callback panics, absent
readbacks and substituted command evidence cannot return success. These records
remain historical after valid pre-dispatch compensation or later owner rotation;
their decoding is never authentication or a dispatch permit.

Admission schema v31 introduces an empty journal only after validating the
exact predecessor. Partial future catalogs, aliases and premature global
references deny migration without repair. The v29 native state catalog/digest
is unchanged for admission versions 29 through 31. Existing history hashes are
not rewritten. Row/global-reference coverage is bijective and binds the exact
historical store owner fence. Oversized, corrupted, deleted or uncommitted
records deny reopening. Policy metadata is sensitive even though raw arguments
and reusable live credentials are not copied into the journal.

This is real preparation retention, not atomic budget capture or full live
credential coupling. It does not attach native security custody to a
dispatch-committed operation. Native dispatch remains unconditionally denied;
generic, split and ordinary combined capture cannot use this journal as an
alternate authority. The next implementation must couple the original full
participant profile, verified live credentials and exact ledger to a dedicated
atomic capture command, then complete native nonce/declassification,
use/outcome/recovery and explicit activation. All prior caller snapshot,
authenticated start/executor delivery/current release, consumer/protocol/SDK,
active-defense/enterprise, retention/scale, platform, dependency-audit, pilot and
release requirements remain open and in scope.

Frozen-source targeted qualification passed with Rust 1.94.1, locked/offline
dependencies, `umask 022`, disabled core dumps and incremental compilation,
one test thread and serial Cargo commands:

- Strict all-target Clippy for `chio-kernel`, `chio-control-plane`,
  `chio-store-sqlite` and `xtask`, plus the production control-plane check.
- Exact callback inventory: two passed, zero failed or ignored, 1,390 filtered,
  in 0.39 seconds. The warning-free source preserves both matching reads and
  denies 15 fault scenarios even when historical data remains.
- Exact participant snapshot inventory: three passed, zero failed or ignored,
  1,626 filtered, in 6.80 seconds. These are actual runtime/approval/DPoP claim
  histories, not a claim of complete native-plus-credential composition.
- Exact kernel egress inventory: eight passed, zero failed or ignored,
  1,384 filtered, in 0.47 seconds.
- Exact native policy inventory: 36 passed, zero failed or ignored, 1,001
  filtered, in 238.05 seconds. The real-ledger cases include corruption and
  restart, wrong-grant rejection, and all three forbidden capture routes after
  retention, requiring unchanged budget and operation history.

The complete frozen-source qualification also passed:

- Full SQLite library: 1,626 passed, zero failed, three pre-existing ignored,
  zero filtered, in 2,840.32 seconds. All 84 declared native custody cases occur
  as passing results in that log, with no missing or undeclared native cases.
  The separately invoked one-test serving-owner helper is not added to the
  library count. The existing retention property, million-receipt scale proof
  and subprocess-helper ignores remain unchanged; retention/scale qualification
  is not waived or claimed complete.
- Complete control-plane `security::adapters::` group: 88 passed, zero failed
  or ignored, 949 filtered, in 240.38 seconds. This supersedes the narrower
  `security::adapters::tests::` run of 68 cases, which excluded 20 adjacent
  module tests. The 36 native policy cases are included in both runs, not
  additional distinct cases.
- Exact native-authority integration: 12 passed, zero failed, ignored or
  filtered, in 70.34 seconds. These preserve forced original admission,
  before-budget joins, native capture refusal and the nonce/preparation boundary.
- Final formatting, source-drift, inventory-runner/verifier self-tests,
  file hygiene, public-surface and whitespace checks passed. No Cargo,
  Rust compiler or graph refresh remained running at closeout.

The flow-gate contract self-test passes 52 exact inventories. This checks gate
wiring and does not execute all behavioral targets. The formal manifest extends
three existing entries and adds 17 source-drift anchors for a total of 171;
all entries match after refreshing 23. Comparison preserves all 154 prior
entries and every non-hash field in the reviewed pre-bless manifest. All 22
mirror-tooling tests passed, with zero failures or ignored and 146 filtered.
Generated proof coverage matches 58 rows and 168 artifacts. These anchors are
not new model-checking or refinement proofs. File hygiene, public-surface policy,
formatting and whitespace checks pass. The AST-only graph refresh completed
with 164,772 nodes, 429,439 edges and 7,051 communities; its SHA-256 is
`3705d7d9dfee50b972fcdd48ffef819073036915e5b6fe3e1419495244eb134f`.
The pre-existing 15 added lockfile lines remain unchanged, with SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

The full SQLite, complete adapter and exact native-authority logs are
`/tmp/chio-native-dispatch-ledger-sqlite-frozen.log`,
`/tmp/chio-native-dispatch-ledger-adapters-complete-frozen.log` and
`/tmp/chio-native-dispatch-ledger-native-authority-integration-exact.log`.
Their SHA-256 values, in that order, are:

```text
c74bacb55ccadf38d6142679c209344b68c414d5ae89073647e061e006835afb
18f4b8aeafb1b31cba5af3b3d0381cd9805acfd97926285c34d6d2f2b6c590e0
0f3d51fd37a55f354072e2d13a94322e317a6b0906941dbd89f70f4b3c22a004
```

The strict Clippy, production check, final mirror check and mirror-tooling logs
are `/tmp/chio-native-dispatch-ledger-clippy-rerun.log`,
`/tmp/chio-native-dispatch-ledger-cp-check.log`,
`/tmp/chio-native-dispatch-ledger-mirrors-final.log` and
`/tmp/chio-native-dispatch-ledger-mirror-tests.log`. Their SHA-256 values are:

```text
68767d813c7a838024309c5234bc33a39453a7dbd9e9f1fb82651ddfc6875543
cc352c983745bc6be8d0315825a107a586ab182c8a9164e500b0a4a27d1b7966
f29ff281167d964bfc2b144200c892d753eb0bd8b5c0ec818e15495aedaf7047
78a988b789a41c6dadb732a2909d644ab47b50ee98c3e1da9124ccfb8795ef2c
```

The candidate has 674 changed/untracked paths across all 11 review slices, with
zero unclassified paths. This is not a fresh audit of every inherited change.
The content fingerprint, excluding this ledger and generated proof coverage,
is unchanged before and after the complete test runs:
`8feba59ecf5a4f772964dc7baf401e359997088e9f8f35bca54cb34b90b048ab`.

All work remains local and uncommitted at HEAD
`8b9f9243905dfa61acac82d83438684940777fe3` in `/tmp/arc-security-launch`.
This checkpoint does not authorize operator database changes, activation,
commits, pushes, merges, workflow repins, hosted jobs or publication. No full
workspace, hosted-CI, platform, pilot or release qualification is claimed.

### Native journal validation and partial-write failures

The composed egress/journal path now rejects unmatched grants and empty,
oversized, malformed or noncanonical policy envelopes before acquiring egress
custody. The already-acquired entry point performs the same checks before
commitment and preserves the existing acquisition on rejection. Previously,
these immutable input errors could be reported only after egress commitment.
The control-plane producer uses the new consume-once
`acquire_and_commit_with_dispatch_ledger` entry point. SQLite independently
validates the grant; the real-ledger fixtures directly probe that store check
and require unchanged operation, budget and journal history after rejection.

Acquisition, egress commitment and preparation-journal retention are still
three separate durable phases. Four actual SQLite abort points, before and
after the journal-row and global-chain-row inserts, now prove that an aborted
journal append leaves neither row nor global reference, while both previously
committed egress phases remain visible. These are all failures before the
outer journal transaction commits, not physical post-commit lost-ack tests.
The fixtures require all three native capture routes to remain denied, no
connector invocation, compensation of only uncaptured invocation quota, and
exact join/egress history after closing every handle and reopening under a
new owner. The old fence is rejected. Existing pre-acquisition failure cases
still require absent egress history; a generic error is no longer mistaken
for proof that every earlier durable phase rolled back.

The default-off SQLite `admission-test-support` feature exposes only those
four fixed abort points as temporary triggers on the serving-owner connection.
It exposes no arbitrary SQL, replacement records or verification bypass.
An initial external-connection injection was correctly rejected by the existing
owner fence; that protection was preserved. The production control-plane build
passes, and its normal/build dependency graph selects only SQLite's `default`
feature. Callback-level lost acknowledgements, panics and substituted readbacks
are tested for both local and already-committed egress paths. That simulated
callback evidence does not replace a future physical post-commit/anchor-failure
qualification.

Frozen-source qualification passed with Rust 1.94.1, locked/offline dependencies,
`umask 022`, disabled core dumps and incremental compilation, one test thread,
and serial Cargo commands:

- Exact ledger callback inventory: three passed, 1,390 filtered, 0.88 seconds.
  It exercises 30 callback-fault cases and 12 invalid-input cases across the
  two phase profiles, in addition to positive confirmation.
- Exact kernel egress inventory: eight passed, 1,385 filtered, 0.44 seconds.
- Exact native-policy inventory: 37 passed, 1,001 filtered, 308.24 seconds.
- Complete control-plane adapter module: 89 passed, 949 filtered,
  311.29 seconds. This includes the 37 native-policy tests, not 37 additional
  distinct tests. Every run above had zero failed or ignored tests.
- Strict all-target Clippy for kernel, control plane, SQLite and xtask;
  production control-plane check; workspace formatting and explicit included
  test-file formatting; file hygiene, public-surface, security-CI and all 52
  exact-inventory structural contracts. The exact-runner/verifier mutation
  self-tests also pass. The structural checks do not execute all 52 inventories.

All 171 formal source-drift entries match. Two entries were refreshed, with
two added method anchors; the other 169 entries and unrelated manifest metadata
are unchanged. All 22 mirror-tooling tests passed, with 146 filtered and none
failed or ignored. Generated proof coverage matches 58 rows and 168 artifacts.
These remain abstraction/source-drift anchors, not new native transaction
model-checking or refinement proofs.

The exact callback, egress, native-policy and full adapter logs are
`/tmp/chio-native-ledger-boundary-exact-callbacks.log`,
`/tmp/chio-native-ledger-boundary-exact-egress.log`,
`/tmp/chio-native-ledger-boundary-exact-policy.log` and
`/tmp/chio-native-ledger-boundary-adapters-full.log`. Their SHA-256 values are:

```text
e9f63ca3cab9196fba1d6cbef4d0c8eb16464a77a17a8ec9ea8d52d0e063a377
4c2c946f548ebf95fd483fee0264ab5efb1b8626ae524889b6afe42c1199fa6f
5d3e9a6e3e96f6410e8d68591b49c34e0cb087fded53c4220fee2309629d60de
7bb7722559d8aedaf0b981caa244bb10130b48a5488d19a8f5be94ffe3676c61
```

Clippy and the production check are recorded in
`/tmp/chio-native-ledger-boundary-clippy.log` and
`/tmp/chio-native-ledger-boundary-production.log`, with SHA-256 values
`cd94faa2b4c4aee4dabd7391a63c9b96abec74416118c8488994a2a0267bae73`
and `0577bd24e61778041ad603292a24ce7f3672c019bbdcff1ce1d52563c7d142d3`.

The candidate contains 676 changed/untracked paths across 11 review slices,
with zero unclassified paths. Its content fingerprint, excluding this ledger
and generated proof coverage, is
`d3c6c5bdfe256c1a7864ac33e397c54db9cfac6cdf145bbf6c4db68386aaefd2`.
The AST-only graph refresh has 164,804 nodes, 429,519 edges and 7,090 communities;
its SHA-256 is
`276159ec2327eb6370c3db33bdb7a49c9f9252f9bb7925fcd3ddbd06ed040c24`.
The pre-existing 15 added lockfile lines remain unchanged, with SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.

This closes early-input-validation and pre-commit partial-write findings, not
the native capture milestone. Dedicated atomic capture must still bind the
original complete authority profile, borrowed live policy and independently
verified credentials to the exact physical participant set and named operation
commitment. Current claim-selection/freshness helpers validate present claims;
their no-attachment success is not proof that a required claim was optional.
DPoP requirements must preserve the kernel's aggregation across all original
matching grants, not just the eventually selected grant. Native nonce,
declassification, use/outcome/recovery and activation remain unqualified, as do
all earlier caller, consumer/SDK, operational, retention/scale, platform,
dependency-audit, pilot and release requirements.

All work remains local and uncommitted at HEAD
`8b9f9243905dfa61acac82d83438684940777fe3` in `/tmp/arc-security-launch`.
The preceding full SQLite run is historical evidence, not a fresh full-library
run for this checkpoint. No full-workspace, hosted-CI, platform, pilot or release
qualification is claimed. No operator database changes, activation, commits,
pushes, merges, workflow repins, hosted jobs or publication are authorized.

### Native atomic capture checkpoint (locally verified, execution closed)

The native path now has a dedicated physical capture implementation. This is
local, uncommitted work in `security/launch-integration`, not native serving
activation or release authorization. Generic, split and caller native capture
remain denied. The security roadmap goal remains open.

- `VerifiedNativeDispatchCredentials` borrows the actual kernel credential
  reservation, live request and original admission. It has no public constructor
  or serialization route. It compares the entire original authority selection,
  including legacy runtime-hook presence, and revalidates actual operation-owned
  runtime, governed-approval and DPoP custody. Missing required claims cannot
  pass through helpers that only validate claims which happen to be present.
- DPoP requirements are aggregated across every originally matching grant.
  Choosing a grant without its own DPoP flag cannot bypass another match's
  requirement. The real SQLite regression selects grant zero without the flag,
  retains the proof required by grant one, and confirms its single claim remains
  owned after capture.
- `PreparedNativeSecurityEgress::retain_for_capture` preserves the original
  affine handle through journal retention. The control-plane policy producer
  keeps its resolver and policy borrowed through capture. Reconstructing a new
  preparation after retention added enough redundant reads to expire a policy;
  the handle now travels through the boundary without increasing its deadline.
- The dedicated SQLite transaction checks physical hold ownership, exact grant
  and operation lease, the original journal and current flow observation, and
  the complete verified claim set. It checks capability expiry and the joint
  authority's capability/ancestor revocations, with final deadline, lease and
  DPoP/approval freshness checks before commit. A private transaction-bound
  witness selects the native participant transition. There is no generic
  `allow_native` switch or digest-only permission.
- Quota capture and `NativeDispatchLedgerDigest` attach atomically through the
  existing budget projection and admission commit chain. Historical preparation
  bytes are unchanged. Operation reads and startup verification bind the
  attachment to its exact preparation and dispatch version. Historical capture
  cannot mint a new live capture authority.
- An explicit, default-off `admission-test-support` checkpoint reaches the real
  evaluation boundary with the actual mutable admission, budget and reservation.
  Normal and nested evaluation share the response handling. Nested evaluation
  passes its admitted runtime metadata. The checkpoint always stops before the
  connector, even after capture succeeds. Captured or unconfirmed custody never
  takes the pre-dispatch refund path.
- The physical fault fixture aborts after an actual budget hold update and after
  the actual admission dispatch update. Both are before the outer transaction
  commit. They must leave the original reservation at `(reserved=1, captured=0)`
  and no dispatch attachment, while preserving the earlier ledger and optional
  committed egress through reopening. These are not post-commit lost-ack or
  process-crash tests.
- Three attachment-contract tests cover all 24 operation-kind and
  broker/budget/nonce combinations, every acquisition and retention phase,
  attachment only with dispatch commitment, persisted round-trip and immutable
  digest replacement refusal. They run in a required exact security inventory.

Code organization remains within the existing lint and size rules. Capture
arguments use named context types. Original-profile accessors live with the
authority-profile implementation, and the two evaluation paths share checkpoint
and ordinary recovery-denial response handling. No size limit or argument-count
lint allowance was added. The admission coordinator has 1,993 lines and the
normal evaluation core has 1,999 lines at this checkpoint.

Local qualification used Rust 1.94.1, locked/offline dependencies, `umask 022`,
disabled incremental compilation and serial test execution. No deadline, stack,
lint, size limit or assertion was weakened. Production Rust remained unchanged
through these runs. The later additions were the three test-only attachment
contracts, their exact inventory and README wording; the expanded unit suite,
exact contracts, Clippy and formatting cover the added tests, and the gate
structure checks cover the final inventory wiring.

| Boundary | Executed result | Log suffix under `/tmp/chio-native-atomic-capture-` |
| --- | --- | --- |
| Native policy, including actual capture/rollback/DPoP | 40 exact tests passed, 377.49 seconds | `exact-policy.log` |
| Kernel ledger callbacks | 3 exact tests passed | `exact-ledger.log` |
| Kernel egress | 8 exact tests passed | `exact-egress.log` |
| Admission-operation filter, including new attachment contracts | 103 passed | `extra-operation-tests.log` |
| SQLite budget atomicity and physical ownership | 6 passed | `budget-tests.log` |
| Complete control-plane adapter filter | 92 passed, 377.32 seconds | `adapters-full.log` |
| Original authority profile | 7 exact tests passed | `extra-profile.log` |
| Native authority integration and generic/split capture refusals | 12 exact tests passed, 70.27 seconds | `extra-native-authority.log` |
| Runtime, approval and DPoP historical snapshots | 3 exact tests passed | `exact-snapshots-final.log` |
| Native attachment contracts | 3 exact tests passed | `exact-attachment-final.log` |
| Finding-market recovery gate | 7 passed with `finding-market` enabled | `extra-recovery-gate.log` |
| Formal source-drift checker tests | 22 passed | `mirror-tests.log` |

Every listed test group had zero failures and zero ignored tests. Overlapping
filters are not additional unique tests. The xtask invocation also visited two
unrelated integration targets with zero selected tests; those are not evidence.
The earlier preliminary three-test run is superseded by the 40-test policy run.

Strict all-target Clippy for kernel, control plane, SQLite and xtask passed in
47.97 seconds. The additional kernel `finding-market` library Clippy check also
passed. Production control-plane `check --lib` passed in 1 minute 14 seconds;
its normal/build dependency tree has SQLite `features=[default]` and no
`admission-test-support` on either SQLite or kernel. The observation hook is not
enabled in that production build. Workspace formatting and explicit formatting
checks for the include-loaded native capture and ledger fixtures passed.

File hygiene, public-surface policy, the security CI contract, all 53 exact
inventory definitions, and runner/verifier self-tests passed. The new attachment
inventory adds one group; the native policy inventory has 40 tests. Structural
validation is not execution of all 53 inventories.

The formal source-drift inventory contains 177 matching entries: six new
abstraction anchors, 16 updated mappings and 155 unchanged entries compared with
the preceding 171-entry checkpoint. No entry was removed and top-level proof
metadata is unchanged. Proof coverage still has 58 rows and 168 artifacts.
These mappings are not proofs of SQL isolation, live credential completeness,
crash safety or native activation; no new formal theorem is claimed.

Selected evidence SHA-256 values:

| Log suffix | SHA-256 |
| --- | --- |
| `exact-policy.log` | `f337fb4d97e22b1e479837612cbecd082f6a11959aa283d34e9bfad42b3475a6` |
| `adapters-full.log` | `8713ca25252375b2425c3b26c27cb4814f3ea81739a25b983af69dd8d4b5f593` |
| `extra-operation-tests.log` | `f6c487fff17c6612fdad56ee2c97be620adbd11952fc57c033cc86f5dcf323b7` |
| `extra-native-authority.log` | `cb778beaa68038d960c59baa19c7e49b5e90d5e8e868c911e20f9afc91221bc4` |
| `exact-attachment-final.log` | `b90ac4628bc74af58ba1b1f16b607e5ec44993a5c3d22f47168273040d2b9aeb` |
| `production-features.log` | `1fb736ab6d46cba1d3c97149853f3866c13759cce064a78317410ecce012ffd8` |

Source fingerprint (excluding this log and generated proof coverage):
`a524dfa5a6ba6aff0a75f84b2df982e3897ee9c34daa4bc77af702654cbf864c`.
The local worktree has 682 changed/untracked paths across 11 review slices,
with no unclassified path. The pre-existing 15 added lockfile lines remain
unchanged, with SHA-256
`869ed1ecc67c8aee36063fe73aeac57cea505d2ddd527a3e4ee77ab746870027`.
The final AST-only graph refresh completed with 164,899 nodes, 429,813 edges
and 7,078 communities. No LLM was used. HTML visualization was omitted by the
existing 5,000-node limit, not by a weakened qualification check. Its log is
`/tmp/chio-native-atomic-capture-graph-final.log`.

Still open: combined nonempty runtime/approval profile and transaction-bound
freshness failure matrices; missing/changed credential and callback-substitution
cases; complete authorization and frozen return-context coupling; genuine
post-commit/anchor lost acknowledgements and process interruption. Capture
acknowledgement qualification must bind the exact budget mutation as well as
the operation successor and independent readback. Native nonce, declassification,
use, outcome, recovery and explicit activation remain open. The other
full-roadmap requirements remain unchanged, including caller execution and
delivery ownership, consumer/protocol/SDK qualification, retention/scale,
platform qualification, dependency audits, operator pilot and release gates.
The preceding full SQLite result is historical; this checkpoint does not rerun
the full library or close receipt-retention issue #1045 or the million-receipt
scale requirement. No full-workspace, hosted, platform, pilot or release
qualification is claimed. All changes remain local and uncommitted at HEAD
`8b9f9243905dfa61acac82d83438684940777fe3`; no operator database mutation,
activation, commit, push, merge, workflow repin, hosted job or publication occurred.

### Native capture acknowledgement checkpoint (partially qualified)

The native capture acknowledgement now has an independent physical budget
readback boundary. This closes the implementation gap where the operation
successor was verified but returned budget metadata and accounting were copied
into live custody without checking them against committed history. Execution
remains closed, and historical readback never creates capture or retry authority.

- The kernel requires a fresh `Captured` decision with the exact successor,
  hold, operation binding, event and original capture authority. Commit ordering,
  timestamp presence, original authorization profiles and valid unique bounded
  quotas are checked before independent readback. `AlreadyCaptured` cannot stand
  in for this affine authority's only live attempt.
- `QualifiedAdmissionProjectionStore::load_native_dispatch_capture` defaults to
  denial. SQLite returns the retained capture decision and current operation in
  one fenced, anchored read transaction. The kernel requires full equality with
  the acknowledgement before updating actual admission or budget custody.
- SQLite follows the exact dispatch version's named admission participant digest
  to its same-owner global budget commitment, not the latest event or a callback's
  event identifier. References are bounded and must be unambiguous. The physical
  event projection hash is recomputed, and the original hold, selected grant,
  capture states, unchanged monetary state, quota deltas and cumulative approval
  identity, currency and checked arithmetic are verified. The existing projection
  decoder and decision builder remain the source of returned budget data.
- A new owner must use its current fence to read the immutable old-owner capture.
  The old fence is rejected, while the original committed decision and preparation
  ledger remain byte-for-byte unchanged. This is historical evidence, not execution
  or recovery activation.
- Default-off `admission-test-support` reply faults run after the actual capture
  transaction and anchor synchronization succeed. Readback faults run after the
  read transaction and connection mutex are released, including panic cases.
  These controls change replies only and expose no arbitrary SQL mutation API.

Initial focused qualification passed: 28 acknowledgement-substitution/error/panic
cases, eight missing/error/panic/changed-readback cases and two lost-acknowledgement
cases with real operation-owned DPoP. All 38 require denial, zero tool and legacy
callback invocations, one committed capture, quota `(reserved=0, captured=1)` and
exact readback after a new-owner reopen. The DPoP cases require the original claim
to remain `RetainedAfterDispatchCommit`, without reclaiming it.

Another 12 cases alter actual committed cost/quota data, remove quota rows, change
the budget commit owner, remove its global commitment or oversize its event
reference, in both local and egress modes. They require both live readback and
owner reopen to reject the corrupted history. Two additional SQLite unit tests
cover exact quota/cumulative deltas, identity, currency, duplicates, incompleteness,
bounds, overflow and underflow. These unit tests do not qualify a combined native
runtime/approval/DPoP profile.

Strict all-target Clippy passed for kernel, control plane, SQLite and xtask.
Five new source-drift entries cover the acknowledgement helper, concrete readback,
physical budget verification, reused decision builder and SQLite trait forwarding.
The existing kernel capture, store capture, qualified-port and budget-hash entries
were updated. All 182 entries match; no symbol or entry was removed, top-level
proof metadata is unchanged and no placeholder hashes remain. Generated proof
coverage remains 58 rows and 168 artifacts. No SQL, crash-safety or activation
theorem was added.

At the user's check-in, all eight exact groups, 103 kernel admission-operation
tests and six SQLite budget tests had completed successfully. The subsequent
96-test adapter suite was interrupted and is not passed evidence. No process from
that campaign remains running. Formal-checker tests, production-feature checks,
final formatting and AST refresh remain pending and will be batched with the next
native milestone, without restarting unchanged completed groups solely because
execution resumed. The exact flow gate declares 44 native-policy tests and a separate
two-test accounting-delta inventory, with 54 inventory groups in its structural
contract. Earlier full-library and workspace results remain historical.

Still open: actual failure between database commit and anchor synchronization,
process interruption, combined nonempty runtime/approval/DPoP freshness and failure
matrices, complete authorization and frozen return context, native nonce,
declassification, use/outcome/recovery and activation. Caller delivery, all consumer
and SDK boundaries, retention issue #1045, million-receipt scale, qualified platform,
dependency audits, operator pilot and release requirements remain unchanged.
This checkpoint does not authorize operator database changes, activation, commits,
pushes, merges, workflow repins, hosted jobs or publication. Local implementation
resumed under the accepted outcome-based execution plan after the check-in.

## Engineering acceptance

Use existing ports, validated types, opaque verified authority, checked arithmetic,
explicit state transitions, and RAII for resource custody. Keep unsafe operations
inside reviewed OS boundary modules with safety invariants. Production domain and
orchestration code must not add unsafe, unwrap, or expect. Security errors deny;
enforced configurations never fall back to legacy paths.

Run focused behavioral tests per change and the original complete security,
schema, formal, dependency, workspace, and release gates before promotion. Every
required filtered gate asserts nonzero execution. Negative controls must fail for
the intended reason; unavailable infrastructure is not evidence of enforcement.

Completion requires qualified packages and runtime, observed pilot and selected
containment promotion, and claim-to-evidence mapping for every advertised
guarantee. Implementation completion, preview publication, hosted qualification,
and operational promotion remain distinct records.
