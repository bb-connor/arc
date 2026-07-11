# WS4 Design: Chio Clearinghouse

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see `2026-07-10-agent-economy-program-design.md`)
- Depends on: `chio_credit::obligation`, an authoritative participant mapping,
  WS1 for dispatch, and a production FROST verifier plus trusted roster/key epoch
  before round-finalization activation
- Claim track: implementation (signed netting intent and reconciliation evidence, never settlement truth)
- Branch: `chio/ws4-clearinghouse` off `main`

## Goal

Reserve a complete single-currency set of canonical obligations and derive a
deterministic, smaller set of settlement intents. V1 cancels bilateral flows,
computes each participant's net balance, and canonically matches debtors to
creditors. It does not treat kernel signers as creditors, ingest the same debt
from two report families, mutate intent after signing, or describe netting as
custody or finality.

## Ground truth and prerequisites

- Exposure-ledger rows and IOU envelopes can describe the same receipt. Reading
  both directly double counts one debt.
- `IouEnvelope.issuer_key` is a kernel signer, not a creditor. Participant and
  destination identity cannot be inferred from it or from `tool_server`.
- A bounded exposure report can omit older obligations. A report at its item
  limit is not proof that an epoch input is complete.
- Cycle cancellation alone is not netting. For `A -> B -> C`, there is no
  cycle, yet balances permit the equivalent `A -> C` settlement.
- A settlement packet cannot contain empty reconciliation fields that are later
  filled without invalidating its signature.

WS4 therefore has two hard prerequisites:

1. The shared producer emits one immutable
   `chio_credit::obligation::ObligationAtom` per receipt-backed debt. It
   deduplicates source artifacts before WS4 and preserves the authoritative
   debtor, payee-bound creditor, amount, and currency. Current settlement
   lifecycle, version, and
   `chio_credit::obligation::ObligationDisposition` are separate authenticated
   records owned by the same module and store contract.
2. A configured participant authority emits a signed, versioned participant
   snapshot that maps every debtor and creditor identity/key to one canonical
   participant id and settlement destination. WS4 has no fallback mapping and
   does not defer this requirement to a later workstream.

## In scope

1. A pure `chio_credit::clearing` module for deterministic v1 netting.
   `chio-credit` already owns the canonical obligation and v1 adds no crate.
2. Exactly one currency per round.
3. Bilateral cancellation followed by participant-balance computation and
   deterministic debtor-to-creditor matching.
4. Transactional input reservation using the shared
   `clearing_reserved` disposition.
5. Immutable round and settlement-intent artifacts, plus separate immutable
   reconciliation artifacts.
6. Complete input/output manifests, disputes, quorum-gated finalization,
   schemas, public verifier coverage, and ladder registration. Artifacts may land
   before the FROST prerequisite; no finalization becomes dispatchable without it.

## Out of scope

- Direct ingestion of exposure reports or IOU envelopes, cross-currency
  conversion, FX evidence, and mixed-currency totals.
- Live participant discovery, inferred organization/key mappings, or a
  participant snapshot signed only by the round proposer.
- Fund movement, custody, on-chain dispatch, new Solidity, and any settlement
  finality claim.
- A clearing network, live-state consensus, or distributed-linearizable truth.
- Partial, paginated, capped, or "best available" round input.

## Design

### Canonical input and reservation

`compute_netting_round` accepts:

- `round_id`, `epoch`, `algorithm_version`, and one `currency`;
- a trusted participant-snapshot body and digest;
- a complete canonical atom manifest; and
- reservation proofs for every atom.

Every atom must:

- have a unique `obligation_id` and canonical digest;
- bind one signed receipt and authoritative payee-bound creditor;
- match the round currency;
- have a separate settlement-lifecycle record that is currently outstanding at
  the submitted version; and
- have a separate `chio_credit::obligation::ObligationDisposition` atomically
  changed from `per_call` to `clearing_reserved { round_id }` by the shared
  store contract.

The control plane first reads candidate versions, then reserves all candidates
in one transaction. If any compare-and-swap fails, no reservation remains and
no round is emitted. Exact duplicate ids, even with equal bytes, reject the
submitted manifest so the caller cannot make cardinality ambiguous. An atom in
`assigned` or `channelized` is ineligible.

Each reservation proof binds the atom digest, old and new versions, prior and
new disposition, round id, and authority signature. The input manifest commits
to the sorted list and its count. A source must provide a closed epoch range,
start/end checkpoints, and completeness proof. Any `has_more` condition,
unconsumed cursor, count mismatch, missing range position, or capped report
rejects the round.

### Deterministic v1 algorithm

All sorting compares canonical participant-id bytes. All addition,
subtraction, and signed balance conversion is checked. Overflow rejects the
round, and every emitted amount must convert exactly to
`MonetaryAmount.units: u64`. There is no saturating result or
`arithmetic_saturated` success state.

1. Verify the participant snapshot, atom digests and source receipt signatures,
   completeness proof, reservation proofs, exact currency, unique ids, and
   canonical order.
2. Aggregate directed amounts by ordered pair
   (`debtor`, `creditor`) with checked `u128` sums.
3. Bilateral cancellation: for each unordered pair, subtract the smaller
   direction from the larger and retain at most one residual direction.
4. Compute each participant balance from the residual graph:
   credits received minus debts owed. Zero balances drop. Partition negative
   balances into debtors and positive balances into creditors.
5. Check that absolute total debtor balance equals total creditor balance.
6. Sort debtors and creditors canonically. Match the first debtor to the first
   creditor for the minimum remaining amount, advance each exhausted side, and
   repeat until both lists are empty.
7. Emit one immutable settlement intent per non-zero match and one participant
   statement per participant. Also emit a deterministic transformation witness
   that lets a verifier replay how every input atom contributed to bilateral
   cancellation, participant balances, and the final intents.

This deliberately reduces `A -> B -> C` to `A -> C` when the values permit.
The canonical greedy match is not claimed to minimize rail fees under every fee
model; it is deterministic, conserves balances, and emits at most
`debtors + creditors - 1` intents.

### Artifacts

All artifacts are RFC 8785 canonical JSON with `deny_unknown_fields`,
versioned schema identifiers, and signatures over immutable bodies.

- `chio.clearing.netting-round-core.v1` binds the round, epoch, currency,
  algorithm, participant snapshot digest, complete input manifest root and
  count, reservation-proof root, dispute window, and generation time. Its
  `round_core_digest` is computed before any output and is the only round
  digest bound by statements and intents.
- `chio.clearing.participant-statement.v1` binds one participant's gross debit,
  gross credit, bilateral adjustment, final net balance, contributing atom
  digests, and `round_core_digest`.
- `chio.clearing.settlement-intent.v1` binds `intent_id`,
  `round_core_digest`, debtor and creditor participant ids, the authoritative
  destination from the participant snapshot, amount and currency, contributing
  reservation root, and dispatch idempotency key. It contains no mutable
  reconciliation field or external transaction placeholder.
- `chio.clearing.output-manifest.v1` binds `round_core_digest`, the complete
  participant-statement, settlement-intent, and atom-transformation roots and
  counts. Those leaves bind only the core, so this digest graph is acyclic.
- `chio.clearing.participant-acceptance.v1` binds the output-manifest digest,
  participant statement digest, participant id, and acceptance signature.
- `chio.clearing.round-finalization.v1` binds `round_core_digest`,
  output-manifest digest, complete participant-acceptance root and count, and
  the governance quorum proof, active roster digest, and quorum key epoch.
  Nothing upstream binds the finalization digest.
- `chio.clearing.settlement-reconciliation.v1` is emitted later and separately.
  It binds the immutable intent digest, WS1 settlement outcome digest, external
  references, observed status, attempt number, and observation time.
- `chio.clearing.zero-intent-reconciliation.v1` is a distinct signed
  reconciliation variant for a finalized round whose output manifest proves
  `settlement_intent_count == 0`. It binds the finalization digest, empty intent
  root, complete input-reservation root, atom ids and expected lifecycle
  versions, outcome `netted_without_rail`, and the fresh lifecycle-transition
  authority digest. It cannot represent a non-empty round.
- `chio.clearing.round-abort.v1` binds the round core, optional output-manifest
  digest, complete reservation root and expected disposition versions, a closed
  reason enum, a durable WS1 dispatch-journal proof that no round intent was ever
  dispatched, and fresh `clearing.round_abort` capability/policy/guard authority.
  The configured disposition authority signs it; a proposer signature or an
  empty external-reference field is insufficient.
- The atom-transformation manifest is a complete deterministic witness, not a
  second obligation record. Each row references an immutable atom digest and
  the bilateral, balance, and intent steps that transformed it. Replaying all
  rows must reconstruct both the complete input root and every output intent.
- `chio.clearing.round-dispute.v1` binds `round_core_digest`, optional
  output-manifest digest, disputing participant, disputed leaf digests, reason
  code, and evidence references.

A statement or intent alone is not a complete round proof. Verification
requires its inclusion in the signed output manifest and a valid finalization
that includes every participant acceptance.

### Lifecycle and exclusive routing

1. Reserve all atoms by transactional compare-and-swap and persist the
   reservation manifest.
2. Sign the round core, compute statements, intents, and transformation rows
   against `round_core_digest`, then sign the output manifest over their roots.
3. Open the declared dispute window. Every affected participant signs its
   statement and the output-manifest digest, thereby accepting the v1 setoff
   and counterparty substitution for this round. A missing participant
   acceptance, valid in-window dispute, or incomplete governance quorum blocks
   finalization.
4. Finalization checks that every atom's separate disposition record is still
   reserved to this round at the expected version, then signs the separate
   round-finalization artifact. An intent is dispatchable only with inclusion
   proofs for the output manifest and finalization plus a FROST aggregate whose
   transcript resolves to the configured active roster and key epoch. Individual
   participant acceptances are attributable evidence, not a fallback quorum
   authorization. With no production FROST provider, finalization returns
   `UnsupportedQuorum` and remains non-dispatchable.
5. WS1 dispatches each intent idempotently. Per-call, assignment, and channel
   settlement must skip all `clearing_reserved` atoms.
6. Each attempt emits a separate reconciliation artifact. It never edits an
   intent or round.
7. Only after every round intent reconciles as settled does one transaction
   advance every input atom's separate settlement lifecycle to satisfied. The
   immutable atoms do not change. A verified `chio.clearing.round-abort.v1` may
   compare-and-swap
   dispositions back to `per_call` only before the first intent dispatch. Once
   any dispatch begins, failure creates a reconciliation incident and the
   remaining intents retry idempotently; no input returns to `per_call` and no
   carried-forward copy is created.

A zero-intent round is not silently treated as settled. After every participant
accepts the output manifest and the governance quorum finalizes it, WS4 emits a
signed `chio.clearing.zero-intent-reconciliation.v1` artifact. Only that typed
artifact, with fresh lifecycle-transition authority and successful expected-
version compare-and-swap, allows the atom lifecycles to advance without a rail
outcome.

Before the first dispatch, a failed round keeps its atoms unavailable to every
other settlement path until the signed abort/release transition succeeds. After
the first dispatch, they remain reserved until all intents settle or an explicit
compensating reconciliation is authorized; they never return directly to
`per_call`. Operational recovery cannot silently duplicate them.

### Participant authority

The participant snapshot is signed by the configured clearing governance
authority and acknowledged by each included participant. It binds participant
id, accepted identity/key aliases, creditor and debtor roles, settlement
destination, validity window, version, and the accepted v1 netting algorithm.
The snapshot must cover every atom and every output destination. Round-specific
participant signatures are still required before finalization. Unknown aliases,
expired snapshots, conflicting mappings, and a proposer self-signing an
otherwise untrusted mapping reject the round.

### Fail-closed errors

Invalid signature, untrusted participant authority, missing participant
acknowledgement, unresolved or conflicting identity, duplicate atom, incomplete
input range, stale lifecycle or disposition version, reservation conflict,
wrong disposition,
mixed currency, checked-arithmetic failure, conservation failure, output count
or root mismatch, transformation-witness mismatch, missing participant
acceptance, in-window dispute, missing quorum, stale reservation at finalize,
missing or inactive FROST key epoch, roster/transcript mismatch, duplicate
dispatch, unauthorized or post-dispatch abort, malformed zero-intent
reconciliation, and reconciliation/intent mismatch all deny.

## Alternatives considered

1. A new `chio-clearing` crate was rejected for v1. `chio-credit` already owns
   the atom and settlement-exposure contract needed by the pure algorithm.
   Extract only if an actual dependency cycle or independent release boundary
   appears.
2. Direct exposure-ledger plus IOU ingestion was rejected because the two can
   represent one receipt. The shared canonical atom is the only input.
3. Cycle cancellation was rejected as the final algorithm because it cannot
   reduce acyclic chains. Balance computation plus deterministic matching does.
4. Cross-currency v1 was rejected. One round has one currency, with no
   conversion or aggregate mixed total.
5. Mutable packets were rejected. Intent and later observations are separate
   signed artifacts.
6. "Use the proposer participant list" was rejected. Settlement routing needs
   an authoritative mapping before WS4 can run.

## Claim framing

WS4 emits deterministic signed intent over a complete reserved snapshot. It is
not custody, finality, a settlement rail, or consensus over live state.
"Clearinghouse" names the netting function. Settlement truth exists only in
separate WS1 reconciliation evidence, and original atoms remain exclusively
reserved until that evidence is applied.

## Testing strategy

- Deduplication: the same receipt represented by exposure and IOU sources
  produces one upstream atom; duplicate ids and digest aliases reject at WS4.
- Algorithm: reverse bilateral flows cancel; cycles cancel through balances;
  `A -> B -> C` reduces to `A -> C`; shuffled inputs produce byte-identical
  outputs; debtor and creditor totals conserve exactly.
- Arithmetic: every checked overflow and signed-balance conversion failure
  rejects, with no truncated or saturated output.
- Completeness: capped reports, unconsumed cursors, missing positions, wrong
  counts, and omitted manifest leaves reject.
- Reservation races: two rounds contend for one atom and exactly one
  transactional reservation succeeds; per-call and channel observers skip the
  winner.
- Identity: missing, expired, conflicting, or proposer-only mappings reject;
  destinations must match the authoritative snapshot.
- Immutability: changing reconciliation data cannot change an intent; mismatched
  reconciliation rejects.
- Digest graph: core, output leaves, output manifest, acceptances, and
  finalization hash in one direction with no circular dependency.
- Authority and lifecycle: every affected participant accepts the full round;
  no atom is satisfied until all intents settle; after the first dispatch a
  failed intent cannot release originals to `per_call`.
- Quorum: complete participant acceptances without the configured FROST
  aggregate, a stale key epoch, or a mismatched roster remain non-dispatchable.
- Zero/abort lifecycle: a typed zero-intent reconciliation requires a finalized
  empty output and fresh lifecycle authority; abort requires proof of zero
  dispatches and stale expected versions reject atom release.
- Lifecycle, schema registry parity, public verifier positives,
  unknown-schema negatives, and workspace gates.

## Implementation phases

1. Prerequisite gate: land the canonical deduplicated
   `chio_credit::obligation::ObligationAtom` producer,
   `chio_credit::obligation::ObligationDisposition` store contract and SQLite
   implementation, complete epoch manifest, and authoritative participant
   snapshot. WS4 stops if any is missing.
2. Land the pure `chio_credit::clearing` single-currency engine and immutable
   artifacts with algorithm, completeness, and verifier tests.
3. Add transactional reservation, propose/report/dispute endpoints, and
   disabled quorum-finalization verification. Still no money movement.
4. After the production FROST verifier and trusted roster/key epoch are live,
   activate finalization, bind immutable intents to WS1 dispatch, and emit
   separate reconciliation artifacts. Prove release/retry without copying an
   obligation. No endorsement-only fallback.
