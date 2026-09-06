# Security roadmap execution and launch ledger

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
| Protocol 2: operation-owned nonce participant | Integrated for in-kernel and remote strict dispatch with cumulative approval | SQLite physical preflight ownership and reversal, write-ahead issuance, reservation, capture and commit, verified cancellation, retained history, signature profile isolation, kernel routing with startup recovery, loopback remote delivery with identity, pre-commit reachability, outcome-unknown terminals, cumulative approval under strict preflight, and process-kill cutpoints on the transport and inside finalization are implemented and exercised end to end; retirement of parked approval-required operations at startup and on an expired retry, and the sidecar's reservations as caller-executed durable operations, are implemented and exercised end to end; provider-signed delivery receipts and delegated sibling shares under durable reservations remain open |
| Protocol 3: policy-owned threshold and signer set | Present | Exact action/capability/policy binding, duplicate signers, expiry |
| Protocol 3: durable replay, collection and federation compatibility | Partially integrated | Canonical collector, kernel-owned original cumulative-request context, native pending-proposal delivery and durable replay components are present; governed active-response sources, sidecar composition and durable session/nonce recovery remain open; preserved bilateral semantics still require qualification |
| Protocol 4: bounded runtime evidence | Present | Existing proof-parity and no-bypass contracts; no broader proof claim |
| Protocol 5: schemas, bindings, adapter preservation | Present | Registry, canonical vectors, four-language codegen and bridge parity |
| Protocol 6: conformance, concurrency, formal and release gates | Hosted run in progress | Draft PR #1117 exact-head lanes: branch regressions repaired, operator re-pins and audits pending, two runner failures to re-run |
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
