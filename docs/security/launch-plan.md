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
| Protocol 3: policy-owned threshold and signer set | Present | Exact action/capability/policy binding, duplicate signers, expiry |
| Protocol 3: durable replay, collection and federation compatibility | Partially integrated | Canonical mandatory-context collector and durable replay are present; production authenticated request context and end-to-end runtime recovery remain open; preserved bilateral semantics still require qualification |
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
open. The proxy's generic upstream header forwarding also needs a reserved-control
credential containment check: operator clients must not attach their control
token to data-plane requests. This gate does not claim to prevent that separate
egress error. Full workspace and hosted qualification, inherited formal drift,
native confinement, packaging and the observed pilot remain open. Automatic
response remains unpromoted.

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
