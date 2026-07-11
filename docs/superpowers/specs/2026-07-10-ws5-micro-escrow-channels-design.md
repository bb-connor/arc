# WS5 Design: Streaming micro-escrow channels

- Date: 2026-07-10
- Program: agent-economy program, wave 3 (see `2026-07-10-agent-economy-program-design.md`)
- Depends on: WS1, `chio_credit::obligation`, existing ChioEscrow devnet
  qualification, and a production FROST verifier plus trusted roster/group-key
  epoch before quorum-authorized close
- Claim track: implementation (devnet-funded v1, no mainnet claim)
- Branch: `chio/ws5-micro-escrow-channels` off `main`

## Goal

Fund one bounded bilateral channel before any covered tool call, reserve capacity
before each dispatch, and settle one cumulative amount at close. Every
receipt-backed debt uses the program's immutable
`chio_credit::obligation::ObligationAtom` and exactly one disposition. A
channelized receipt never also enters per-call, assignment, or clearing
settlement.

## Ground truth and prerequisites

- A post-persist observer is too late to choose a settlement route. At that
  point the tool has delivered value and a per-call observer may already have
  acted.
- A budget reservation is not channel funding. V1 requires a rail that has
  already locked the full channel bound for the named payer and payee.
- A bare EIP-3009 authorization locks no funds and can be withheld at close. It
  does not bound recoverable exposure.
- The existing ChioEscrow has a transferable admin, token allowlist, and pause.
  Pause blocks release but not post-deadline refund, so an admin can delay a
  beneficiary release until the refund branch wins. V1 treats that as an
  explicit devnet trust and liveness limitation; it does not claim
  non-discretionary or production custody.
- The current x402 adapter performs prepayment and local capture/release
  bookkeeping; it does not expose the partial, refundable hold needed for a
  cumulative channel.
- `SettlementPolicyConfig::tier_for_amount` must be applied to the immutable
  channel bound. Applying it to a close submitter's cumulative amount lets that
  submitter shorten the dispute window.

V1 therefore supports exactly one funded rail: an existing ChioEscrow deposit
on the qualified local devnet. The escrow state must prove the full bound is
deposited and bind the payer/refund owner, payee, token, chain, and deadline.
The proof must also bind the complete immutable `EscrowTerms`, the creation
event, the operator and operator-key hash, and a canonical finalized block. The
current `read_escrow_snapshot` reads unpinned `latest` and omits several of those
fields, so it is not sufficient evidence for channel open.

The existing Rust `prepare_merkle_release` path already selects
`partialReleaseWithProofDetailed` for
`EscrowExecutionAmount::Partial`. It releases the final cumulative amount, and
the existing post-deadline refund returns the remainder. The two transactions
are not atomic, and the spec makes no stronger claim.

The live contract does not understand a channel reservation, channel close
digest, or FROST proof. It authorizes a proof release from the beneficiary when
the escrow is live, the amount fits, the escrow's operator key is still current,
and the leaf is included under a published root. The Rust prepare, root
publication, and generic `submit_call` surfaces likewise do not currently
consult channel state. WS5 must add one reservation-aware publisher gate across
all three surfaces. This gate is off-chain operational control, not additional
Solidity authority. A beneficiary plus the relevant operator/root-publisher or
settlement-key holders can bypass it by calling the existing contract paths
directly. V1 is therefore limited to controlled local-devnet qualification and
does not claim Byzantine-safe custody or an on-chain channel protocol.

## In scope

1. A pure `chio_settle::channel` module for funding evidence, open-intent,
   funding acknowledgement, open, reservation, state, close, dispute, and
   release-authorization artifacts. V1 is already web3/devnet-scoped, so the
   existing settlement owner is the actual dependency boundary and v1 adds no
   crate.
2. A signed channel open bound to one fully funded ChioEscrow deposit.
3. Signed pre-dispatch capacity reservations.
4. Exact-sequence, digest-chained cumulative states over channelized receipts.
5. Exclusive disposition routing through the shared
   `chio_credit::obligation::ObligationDisposition` store contract and its
   `platform/chio-store-sqlite` implementation.
6. Cooperative and contested close with a dispute window fixed from the bound.
7. Reuse of the existing ChioEscrow partial-release and post-deadline refund
   runtime, devnet only.
8. Schemas, public verifier coverage, unknown-schema negatives, and ladder
   registration for `channel_close`.

## Out of scope

- EIP-3009, x402, Circle, generic payment-adapter, unfunded, or credit-backed
  channels in v1.
- New Solidity, atomic dual payout, mainnet or public-testnet deployment, or a
  custody claim beyond the verified existing escrow.
- Mutable bounds, top-up, multi-currency channels, cross-participant netting,
  assignment, and partial or secondary ownership.
- Post-dispatch fallback from channel settlement to per-call settlement.

## Design

### Funding and open

Before signing `chio.channel.open-intent.v1`, both parties verify
`chio.channel.funding-evidence.v1`, produced from one block-pinned escrow read
and canonical inclusion/finality evidence. It contains:

- chain id, escrow contract, escrow id, and the full immutable `EscrowTerms`:
  capability id, depositor, beneficiary, token, max amount, deadline, operator,
  and operator-key hash;
- deposited, released, and refunded state at the pinned block;
- the successful creation transaction hash and decoded `EscrowCreated` event,
  including log index, with fields matching the queried terms;
- pinned block number, block hash, block timestamp, observation time, required
  confirmations, observed confirmations, and finality status; and
- a block-pinned identity-registry observation proving the named operator is
  active and its current key hash equals the escrow's immutable key hash.

Open validation then requires:

- `terms.maxAmount == deposited == channel bound`;
- no amount has already been released or refunded;
- beneficiary equals the channel payee;
- refund owner equals the channel payer;
- token, currency, chain id, and contract address match;
- `close_submission_cutoff = escrow_deadline -
  fixed_finality_broadcast_margin` is checked, strictly before escrow expiry,
  and no earlier than `channel_expiry + dispute_window`; and
- the escrow reference is not reserved by another channel.

The reader must use `eth_call` at the recorded block tag, then re-read that
block number and require the same block hash before accepting the evidence. A
floating `latest` result, failed creation receipt, missing or mismatched creation
event, non-final block, inactive operator, or key mismatch rejects. The open
intent binds the original web3 dispatch digest, operator address, operator-key
hash, and funding-evidence digest; later code cannot substitute a new dispatch,
operator, or rotated key.

Both parties first sign the open intent. The configured channel settlement
authority owns one durable funding-reservation registry in
`platform/chio-store-sqlite`. It atomically compare-and-swaps the escrow
reference from unreserved to `open_intent_digest` and emits a signed funding
acknowledgement with the old and new store versions. Both parties accept only
that configured authority, then sign the final open binding both prior digests.
A private channel-open artifact cannot replace this serialization point or
reuse one deposit for two channels. Missing, stale, or unfinalized funding
evidence rejects open.

The same registry is the exclusive off-chain lifecycle for the escrow reference:
`unreserved -> opening(open_intent_digest) -> open(channel_id) ->
closing(close_digest) -> released | refunded | incident`. Every transition is a
versioned compare-and-swap. An `incident` remains reserved until an authenticated
operator resolution proves the escrow is canonically released or refunded; age
or a failed worker never returns it to `unreserved`.

The final open must be signed before the funding acknowledgement expires. If it
is not, the authority may compare-and-swap that unused reservation back to
unreserved; an expired acknowledgement can never open a channel.
After both open signatures verify, the authority must compare-and-swap the exact
`opening(open_intent_digest)` version to `open(channel_id)`. No request-level
capacity reservation or tool dispatch is allowed while the escrow remains only
`opening`.

The funding authority key, authority id, and epoch resolve from trusted runtime
configuration. They are not accepted from an embedded acknowledgement key, and
rotation cannot make two authorities current for the same escrow namespace and
epoch.

The escrow's operator-key hash is immutable. Before root publication and again
before release broadcast, the publisher reads the identity registry at a pinned
canonical block and requires the original operator to remain active with that
exact key. A rotation that changes the current key strands the proof-release
path for this escrow; WS5 freezes the channel, records a reconciliation incident,
and waits for the contract's post-deadline refund. It never rewrites the open to
a new key or claims that rotation preserves release liveness.

The dispute tier and duration are selected once from `bound.units` and copied
into the open artifact. They are immutable. No close or dispute recomputes the
tier from `cumulative_owed`.

### Artifacts

All artifacts are RFC 8785 canonical JSON with `deny_unknown_fields`,
versioned schema identifiers, and signatures over immutable bodies.

- `chio.channel.open-intent.v1` binds `open_intent_id`, payer and payee
  identities and keys, currency, bound, expiry, immutable dispute tier and
  duration, fixed finality/broadcast margin, close-submission cutoff,
  original web3 dispatch digest, ChioEscrow reference, funding-evidence digest,
  original operator and operator-key hash, participant-snapshot digest, and both
  party signatures.
- `chio.channel.funding-evidence.v1` is the block-pinned evidence described
  above. Its digest covers the complete escrow terms and state, creation event,
  identity-registry observation, block identity, observation time, and finality
  assessment. The configured funding authority signs only after reproducing
  those checks. It is evidence, not authority to reserve or release the escrow.
- `chio.channel.funding-acknowledgement.v1` is signed by the configured funding
  authority and binds `open_intent_digest`, escrow reference, prior
  unreserved state/version, new reserved state/version, `reserved_at`, and
  acknowledgement expiry. It does not bind the later open digest.
- `chio.channel.open.v1` binds the open-intent and funding-acknowledgement
  digests, sets
  `channel_id = sha256(canonical_json(["chio.channel.id.v1",
  open_intent_digest, funding_acknowledgement_digest]))`, commits the canonical
  sequence-zero state digest, and carries both party signatures. This ordering
  is non-cyclic and lets an offline verifier prove terms, unique reservation
  acknowledgement, initial state, and final consent.
- `chio.channel.reservation.v1` binds `reservation_id`, channel and open
  digests, stable request reference, exact next sequence, expected prior state
  digest, maximum charge, expiry, disposition-store expected version, and the
  payer/channel-authority signature. It is signed and durably persisted before
  tool dispatch.
- `chio.channel.state.v1` binds `channel_id`, exact `seq`,
  `prev_state_digest`, `cumulative_owed`, ordered receipt-id root and count,
  the new receipt and `chio_credit::obligation::ObligationAtom` digests,
  reservation digest, and payer signature. A payee countersignature marks
  acceptance.
- `chio.channel.close.v1` binds the open digest, close kind, final state digest
  and sequence, intended payee allocation (`final_cumulative_owed`), expected
  refund only if that intended release succeeds, immutable dispute duration, and
  required signatures. It records no mutable rail result and never labels an
  expected remainder as an observed refund.
- `chio.channel.dispute.v1` binds the close digest, the competing state and
  chain proof, reason, and submitter signature.
- `chio.channel.release-authorization.v1` is a single-use, durable off-chain
  publisher record signed by the configured publisher authority. It binds the
  escrow reservation and version, open and close digests, intended release
  amount, final state, verified FROST proof digest, trusted roster, group-key
  epoch, original operator/key hash, publication root, and close-submission
  cutoff. It is consumed by compare-and-swap at broadcast; it is not an on-chain
  authorization recognized by ChioEscrow.

Rail release and refund observations are separate reconciliation artifacts
owned by WS1; WS5 adds the channel-specific event, allocation, and reservation
validation below. No channel artifact duplicates or mutates the immutable
`chio_credit::obligation::ObligationAtom` or embeds mutable settlement
lifecycle as atom state.

### Sequence and fork rules

The open artifact commits a sequence-zero state digest with zero cumulative
amount and an empty receipt root. Every later state must satisfy all of:

- `seq == prior.seq + 1`;
- `prev_state_digest == digest(prior_state)`;
- the ordered receipt set appends exactly the reserved receipt;
- `cumulative_owed == prior.cumulative_owed + receipt.cost_charged` using
  checked arithmetic;
- the charge does not exceed the signed reservation; and
- cumulative amount does not exceed the immutable bound.

The same sequence and same digest is idempotent. The same sequence with a
different digest is equivocation, but signature strength determines its effect.
If exactly one branch is mutually signed and the conflicting branch is only
payer-signed, freeze new calls and preserve both proofs, but keep the mutually
signed branch as the closeable state. A unilateral payer fork cannot erase an
accepted balance. If two conflicting branches are both mutually signed, block
cooperative close and make their last common mutually signed ancestor the
highest automatically closeable state unless both parties later co-sign one
resolution branch. If neither branch is mutually signed, neither advances the
closeable prefix. A higher sequence does not win unless every intermediate state
and digest link verifies. There is no "latest integer wins" shortcut.

### Pre-dispatch reservation and exclusive disposition

For each request:

1. Select channel mode before any tool execution.
2. Verify the funded open and current state, then transactionally reserve the
   quoted maximum from
   `bound - cumulative_owed - pending_reservations` using checked arithmetic.
3. Sign and durably persist `chio.channel.reservation.v1`. A reservation failure
   denies this channel attempt before dispatch.
4. Dispatch the tool only after the kernel request context carries the
   reservation and open digests.
5. Build the signed receipt with a channel binding containing `channel_id`,
   open digest, reservation digest, exact sequence, and settlement mode
   `channelized`.
6. Before any settlement observer can enqueue work, one durable transaction
   persists the receipt, produces the immutable
   `chio_credit::obligation::ObligationAtom` once, and creates its authenticated
   disposition as `channelized { channel_id, reservation_id }`. The per-call,
   assignment, and clearing paths must skip it. A receipt carrying a channel
   binding is never eligible for per-call dispatch even when the disposition
   projection is temporarily unavailable.
7. Convert the capacity reservation to the next cumulative state. Release only
   the unused difference between reserved maximum and actual receipt charge.

If the durable receipt/atom/disposition transaction cannot commit after
dispatch, RFC-0003 records an outcome-unknown incident bound to the channel,
request, and reservation. The capacity reservation and escrow reservation stay
locked. V1 does not claim that WS1 or RFC-0003 can replay this channel projection:
the current journals do not carry an idempotent channel-projection payload, and
their default post-effect recovery is incident/dead-letter. No observer,
receipt scan, or retry worker may synthesize the missing atom or state. An
explicit future repair path must first define a durable idempotency key and
complete projection payload; until then resolution is operator-reviewed evidence
only. If the receipt did commit, its channel binding remains exclusive even when
a later channel-state projection fails. Neither case falls back to per-call
settlement.

A caller may choose a new per-call attempt only when channel selection or
reservation failed before dispatch and a separate per-call authorization
succeeds before that new dispatch.

Zero-charge or denied calls consume no
`chio_credit::obligation::ObligationAtom`; their capacity reservation is
released through the authenticated reservation audit.

### Close and dispute

A cooperative close requires both parties to sign over the newest contiguous
mutually signed state. A contested close posts the best valid contiguous state
and opens the exact duration committed in `chio.channel.open.v1`. A dispute can
replace it only with a valid descendant chain. An equal-sequence different
digest with exactly one mutually signed branch proves unilateral equivocation but
does not invalidate that branch. Two conflicting mutually signed branches may
finalize automatically only at their last common mutually signed ancestor unless
both parties later co-sign one branch. The `channel_close` n-of-m decision cannot
pick an arbitrary branch or amount; arbitrary arrival order never resolves a
fork.

Finalization and release broadcast must complete no later than the immutable
`close_submission_cutoff`, leaving the fixed margin before escrow expiry for
chain inclusion/finality. Missing the cutoff blocks release, emits a
reconciliation incident, and leaves the escrow remainder for the contract's
post-deadline refund. The runtime never attempts a release after expiry.

The ladder class for a settlement commitment is `n_of_m`. Until the production
FROST verifier and configured trusted active roster, group key, key epoch, and
rotation rules exist, all channel close finalization and release dispatch remain
disabled. Party signatures and independent endorsements cannot substitute for
that aggregate authorization.

The release path is one reservation-aware Rust publisher boundary, not a
channel-only helper beside bypassable generic functions:

1. Before calldata preparation, the boundary loads the durable reservation by
   `(chain_id, escrow_contract, escrow_id)`. A reserved escrow requires the exact
   open, close, final-state, and reservation versions plus a production-verified
   FROST proof over the close digest and intended amount. It revalidates the
   funding evidence, cutoff, canonical pinned escrow state, and original active
   operator/key, then compare-and-swaps `open -> closing` and writes one
   `chio.channel.release-authorization.v1`.
2. `prepare_merkle_release` and
   `prepare_merkle_release_root_publication` must require that same verified
   authorization context for a reserved escrow. The prepared release and root
   publication bind its digest, close digest, intended amount, and expected
   reservation version. An ordinary generic preparation call for a reserved
   escrow rejects.
3. The broadcast boundary decodes ChioEscrow release calldata, looks up its
   escrow reservation again, rechecks the pinned operator/key and cutoff, and
   compare-and-swaps the exact authorization to consumed before calling
   `submit_call`. A reserved escrow cannot use the ordinary signature-release
   path or a prepared call whose close, amount, root, receipt hash, or
   authorization digest differs. Failed submission leaves `closing` reserved
   and records an incident; it never unlocks ordinary reuse.
4. Root publication and release broadcast use separate successful transaction
   receipts and canonical finality evidence. Publishing a root is not evidence
   that ChioEscrow released funds.

Preparation, root publication, and broadcast each reload the durable registry;
passing a previously loaded object is not a substitute. Preparation performs the
`open -> closing` compare-and-swap, root publication requires that exact
`closing` version and authorization digest, and broadcast consumes that same
version. Any intervening state or version change rejects.

The production runtime must not export an unguarded `submit_call` route for
reserved ChioEscrow release selectors. This closes the supported Rust path only.
The Solidity contract still does not verify the channel reservation, close
digest, or FROST proof. Its beneficiary and operator/root-publisher or settlement
key holders remain trusted not to bypass the Rust gate, including through
`releaseWithSignature`. That trust is acceptable only for the controlled local
devnet claim.

At finalization and reconciliation:

1. The quorum-authorized close decision produces a signed, anchored Chio
   receipt binding the close digest and `final_cumulative_owed`. For a non-zero
   amount below the bound, its inclusion proof is passed to existing
   `prepare_merkle_release` with `EscrowExecutionAmount::Partial`, which
   prepares `partialReleaseWithProofDetailed` for the escrow beneficiary. The
   channel adapter first verifies that the receipt, close, final state, and
   supplied execution amount all match. A full-bound close uses the existing
   full release; a zero close performs no release.
2. `final_cumulative_owed` is the intended payee allocation, not an observed
   transfer. The actual released total comes only from successful, canonically
   finalized ChioEscrow release events and matching block-pinned state.
3. After the immutable escrow deadline, the contract refund is derived exactly
   as deployed: `actual_refund = deposited - actual_released`. A finalized
   `EscrowRefunded(escrow_id, actual_refund)` event and matching refunded state
   prove it. It is not `bound - final_cumulative_owed` when release failed,
   paused, missed cutoff, reorged, or was stranded by key rotation.
4. Reconciliation records intended payee allocation, actual released total,
   actual refund, and
   `unpaid_payee_shortfall = final_cumulative_owed - actual_released` with checked
   arithmetic. Actual release above the intended allocation is a security
   incident. After a canonical refund, actual release plus actual refund must
   equal the deposited amount.

The protocol is never the payee. Emergency controls and key rotation can change
the realized allocation by preventing release before refund; they cannot rewrite
the close's intended allocation. Any unpaid shortfall is an explicit incident,
not silently relabeled as a successful channel close.

### Rail reconciliation

WS5 does not use the current caller-supplied `observed_amount` or infer an
execution from aggregate escrow state. Release and refund projections require:

- an EVM transaction receipt with `status == true`, the expected ChioEscrow
  destination, the expected beneficiary sender for release, and a block
  number/hash that remains canonical through the immutable bound-derived
  confirmation and dispute tier;
- decoded contract logs from that receipt. A release must contain exactly the
  expected `EscrowReleased` or `EscrowPartialRelease` event for the escrow id,
  released amount, and close-receipt hash. A refund must contain
  `EscrowRefunded` for the escrow id and refund amount;
- a post-transaction `getEscrow` read pinned to the receipt block, with complete
  terms and state matching the funding evidence and event. Partial-release
  `remaining`, cumulative `released`, and refund arithmetic must agree; and
- an idempotency key over chain id, transaction hash, log index, and event
  signature. A byte-identical replay is a no-op; conflicting evidence is an
  incident.

A successful transaction with a missing, duplicate, wrong-contract, wrong-id,
wrong-receipt-hash, or amount-mismatched event is not settlement evidence. A
failed transaction, floating-latest snapshot, caller-provided amount, or
caller-provided observation time, non-final block, or reorged block cannot
advance realized allocation; observed time comes from the pinned block. Once a
canonical refund event and `refunded = true` state are recorded, refund is
terminal and recovery returns no `ExecuteRefund` or retry action. A failed refund
submission may be retried only while pinned state still proves
`refunded = false`; release or refund ambiguity freezes the reservation and emits
an incident.

### Un-countersigned tail and per-call behavior

The closeable automatic balance is the newest contiguous mutually signed state.
Later payer-signed states form an un-countersigned tail. They remain
`channelized`, keep their reservations locked, and are retried for
countersignature until channel expiry. They do not enter per-call settlement.

At expiry, a contested close may finalize only the last valid mutually signed
prefix. Every tail receipt becomes an explicit reconciliation incident, and
its reserved escrow remainder follows the refund leg. This v1 liveness limit is
visible and testable: it can underpay a non-responsive payee, but it cannot
double-charge the payer. A future protocol may add an authority-backed
receipt-only tail proof; v1 does not invent one.

New calls after a channel is full, frozen, closing, or expired use per-call mode
only if that mode is selected and authorized before their own dispatch.

### Fail-closed errors

Unfunded or reused escrow, stale funding proof, payer/payee/token/chain mismatch,
deadline too short, missing open signature, reservation conflict, insufficient
capacity, stale disposition version, post-dispatch route change, sequence gap,
prior-digest mismatch, equal-sequence fork, receipt-root mismatch, unbound
receipt, currency drift, checked-arithmetic failure, cumulative above bound,
mutable dispute tier, invalid state signature, missing close authority, missing
or stale FROST proof, unguarded reserved-escrow publication/broadcast, operator
rotation, failed transaction status, missing or conflicting contract event,
non-canonical block, caller-supplied realized amount, and rail reconciliation
mismatch all deny or freeze as specified.

## Alternatives considered

1. A new `chio-channel` crate was rejected for v1. `chio-settle` already owns
   the only shipped rail and close runtime. Extract a rail-neutral contract
   only when a second genuinely funded non-web3 rail requires it.
2. A post-persist metering driver with per-call fallback was rejected. It
   selects the route after value delivery and can settle one receipt twice.
3. EIP-3009 was rejected as a v1 bound. An authorization is not funded custody,
   and a payer can withhold the close authorization.
4. X402 and generic adapter holds were rejected because the current
   implementations do not prove partial refundable funding. Add a rail only
   when its real semantics satisfy the same open and close invariants.
5. A new channel contract was rejected under the freeze. The existing escrow's
   partial release plus delayed refund is sufficient for a devnet v1, with the
   non-atomic boundary stated.

## Claim framing

V1 is a devnet implementation over a verified, fully funded existing
ChioEscrow deposit. Channel state is signed intent and receipt-referential
evidence. Release and refund finality are separate rail observations. No
mainnet, public-testnet, atomic-close, generic-rail, non-discretionary custody,
admin-free, or on-chain FROST-enforcement claim is made. The existing
pause/allowlist/admin model, beneficiary release caller, operator/root-publisher
keys, settlement key, and immutable operator-key rotation behavior remain
explicit trust assumptions. The Rust reservation/FROST gate qualifies only the
supported controlled-devnet publisher; it cannot prevent direct contract calls
by those key holders and blocks promotion pending a contract-enforced authority
boundary plus external assurance.

## Testing strategy

- Funding: insufficient, reused, already released, wrong beneficiary/refund
  owner, wrong asset/chain, incomplete escrow terms, wrong max amount, operator
  or key mismatch, failed/mismatched creation event, floating-latest or reorged
  state, stale proof, missing funding acknowledgement, and short deadline or
  finality margin each reject open. A block-pinned happy path verifies the full
  terms, event, identity-registry state, observation time, and finality fields.
- Open digest graph: intent, funding acknowledgement, and final open verify in
  one direction with the derived channel id and no circular hash.
- Pre-dispatch gate: no tool execution occurs before a signed durable
  reservation; reservation failure can start only a separate newly authorized
  per-call attempt.
- Persistence ordering: receipt, immutable atom, and `channelized` disposition
  commit before observers run. A post-dispatch projection failure creates an
  outcome-unknown incident and leaves both capacity and escrow reservations
  locked; no journal, observer, or scan automatically replays it or triggers
  per-call dispatch.
- Exclusive routing: a channelized atom is skipped by per-call, assignment, and
  clearing paths; a post-dispatch failure remains channelized.
- Capacity and arithmetic: reserved maximum, actual-cost release, bound edge,
  overflow, intended versus realized allocation, release failure/partial
  release, `actual_refund = deposited - actual_released`, unpaid-payee
  shortfall, over-release incident, and exact actual-release-plus-refund equality
  after canonical refund.
- Sequence: skipped state, wrong previous digest, reordered receipts,
  same-digest retry, equal-sequence fork, and disconnected higher sequence. A
  payer-only fork against a mutually signed state freezes new calls but cannot
  roll the closeable balance back; two mutually signed forks close no later than
  their last common mutually signed ancestor.
- Dispute: low and high submitted cumulative amounts produce the same
  bound-derived window; a fork closes no later than the last common mutually
  signed ancestor. Release after the close-submission cutoff rejects without a
  broadcast attempt.
- Tail: missing countersignature never triggers per-call settlement; expiry
  closes the signed prefix and emits incidents for the tail.
- Devnet rail: fund ChioEscrow, prepare and broadcast the existing partial
  release from an anchored close receipt through the production FROST verifier,
  wait through the fixed deadline, refund the contract-derived actual remainder,
  and reconcile both immutable outcomes. Missing or stale roster/group-key
  epochs reject before preparation, root publication, and broadcast.
- Release authority: the same durable reservation, close digest, FROST proof,
  original operator/key, and reservation version are required at preparation,
  root publication, and broadcast. Generic proof or signature release through
  the supported Rust runtime rejects a reserved escrow. Key rotation freezes and
  incidents the release path. A test also documents that direct key-holder
  contract calls remain outside this off-chain guarantee.
- Release binding: changing the close digest, final state, receipt digest,
  execution amount, published root, authorization digest, or reservation version
  independently rejects before broadcast.
- Reconciliation evidence: failed receipts, wrong destination, missing or
  duplicate release/refund events, wrong escrow/amount/receipt hash, state/event
  mismatch, caller amount drift, and non-canonical blocks reject. A finalized
  refund is terminal and never returns `ExecuteRefund` or another retry.
- Schema registry parity, public verifier positives, unknown-schema negatives,
  and workspace gates.

## Implementation phases

1. Land pure `chio_settle::channel` artifacts and validators, including exact
   sequence/fork rules and the immutable bound-derived dispute window.
2. Land pre-dispatch capacity reservation and shared
   `chio_credit::obligation::ObligationDisposition` routing and SQLite audit.
   Prove that no post-dispatch fallback exists and that projection failure
   creates an incident with locked reservations rather than unsupported replay.
3. After the production FROST prerequisite is live, reuse the existing
   ChioEscrow partial-release and refund paths behind the reservation-aware
   prepare/root-publication/broadcast gate. Add the complete block-pinned funding
   reader and event-bound reconciliation, then run the funded devnet end-to-end
   test. This phase is required for v1, not optional; without the verifier and
   guarded publisher, artifacts may land but close stays disabled and v1 is
   incomplete.
4. Add any other rail only after its real funded hold, partial release, refund,
   idempotency, and reconciliation semantics pass the same contract.
