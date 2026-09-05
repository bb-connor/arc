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
| Protocol 2: operation-owned nonce participant | Partially integrated | Atomic reservation/readiness and retained history are implemented; commit, cancellation, issuance/preflight identity and runtime recovery remain open |
| Protocol 3: policy-owned threshold and signer set | Present | Exact action/capability/policy binding, duplicate signers, expiry |
| Protocol 3: durable replay, collection and federation compatibility | Partially integrated | Canonical collector, kernel-owned original cumulative-request context, native pending-proposal delivery and durable replay components are present; governed active-response sources, sidecar composition and durable session/nonce recovery remain open; preserved bilateral semantics still require qualification |
| Protocol 4: bounded runtime evidence | Present | Existing proof-parity and no-bypass contracts; no broader proof claim |
| Protocol 5: schemas, bindings, adapter preservation | Present | Registry, canonical vectors, four-language codegen and bridge parity |
| Protocol 6: conformance, concurrency, formal and release gates | Pending qualification | Exact inventories and final candidate hosted gates |
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
