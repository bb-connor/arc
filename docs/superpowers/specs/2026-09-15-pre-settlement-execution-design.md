# Pre-settlement native execution evidence

## Objective and authorization

Continue the accepted registered-work delivery at
`df2e7ef0ed1e1ba3ba5ef244e2247347b2c0f3e0` in the existing isolated
`feat/funded-native-admission` worktree. The user authorized the next execution
step and local qualification/commit. The original paper checkout, other worktrees,
public networks and real funds remain outside this delivery.

This is a protocol extension: attest an original native execution before its
financial successor completes, then use that evidence in Finding acceptance.
The existing Finding verifier's mediated-spend profile remains unchanged.

## Design choice

Use an explicit `chio.pre_settlement_execution.v1` receipt-semantics profile on
the existing signed `ChioReceipt` envelope. A new closed `execution_evidence`
metadata block binds the original authority, operation, request, hold,
authorization, retained native outcome, resolved output, complete terminal
post-return evaluation, output guard verdict and pricing verdict. It states
`execution_confirmed`; it does not assert output release or financial settlement.
There is no financial, mediated-spend or budget-authority metadata.

Alternatives were rejected for concrete reasons. Reusing the final payment
receipt would create a circular dependency. Retrofitting the mediated-spend nonce
preflight would change admission and accounting authority beyond the evidence
step. A provider-generated attestation would not prove the trusted guard outcome.

## Kernel and durable store

`ChioKernel::export_durable_execution_evidence(&ToolCallRequest)` authenticates
an existing retained request and returns one persisted `ChioReceipt`. It cannot
create an operation, execute a tool, reserve a hold or settle money. First export
requires a Finalizing native operation with retained original signing identity,
a resolved post-return evaluation, exact resolved output bytes and an allow
verdict. Unsupported caller, security-release or incomplete-output provenance
fails closed. Historical records lacking the frozen signing identity cannot use
a current replacement signer.

The signer runs outside the mutation sequencer. After it returns, the original
lease, fence and source records are revalidated at fresh trusted time. A qualified
store token authorizes one atomic, immutable per-operation evidence projection.
The canonical receipt is retained with the tool-outcome participant commitment,
so deleting/replacing an evidence row or rolling back its projection fails
anchored verification. New trait methods default to unsupported.

The SQLite tool-outcome schema advances from exact v3 to v4 through an explicit
additive migration. Existing release tables remain verified. No final receipt
projection or operation terminal state changes. The receipt is appended without
creating a settlement-observer job. Retries, process restart and later settlement
return the first exact receipt bytes without re-signing or redispatching.

## Verifier and original agreement

A shared core validator checks the explicit execution profile, strict original
signature, admitted kernel key, closed metadata, bounds, allow semantics and
resolved content hash. Existing `chio.mediated_spend.v1` validation is unchanged.
The new Finding profile can establish receipt authenticity and checkpoint
membership through existing strict receipt, key-standing, chronology and Merkle
wrapper checks. Metered exposure and settled spend remain unavailable because an
execution-only receipt supplies neither authority. No facet is inferred from
another facet.

The funded surface provisions a v2 verifier context before signing the agreement:
separate checkpoint and status signers, pinned production/checkpoint/governance
standing, and required artifact-integrity, receipt-authenticity,
checkpoint-membership and guarantee-consistency facets. Its private checkpoint
key stays in the private state directory. The original agreement's existing
context digest and ordered requirements bind this profile. Historical v1 contexts
and their empty-evidence assessments retain their original meaning.

The provider retains a bounded canonical evidence bundle containing the kernel
receipt, checkpoint prefix, exact inclusion wrapper and transparency records.
The Finding references this receipt/checkpoint and remains asserted-class with
explicit verified facets. Submission and decision envelope fields remain stable.
Both decision creation and replay derive the complete assessment from the exact
retained bundle at the original evaluation time. Receipt source identities and
input/output hashes must equal the original native binding before any claim.
Independent Python verification checks the public receipt, signature, original
binding and checkpoint proof rather than trusting a Rust success flag.

## Failure and recovery

Missing, changed, late, unpinned or noncanonical evidence cannot create a financial
decision. Unavailable required financial backing still permits only the original
timeout/refund. Output-guard denial, uncertain execution and undispatched work
cannot export positive execution evidence. An earned child's original evidence
and payment survive its parent's death.

Qualification includes semantic substitution, cross-operation/source mutation,
unknown raw fields and duplicate keys, signer/standing/checkpoint changes,
historical replay, source-store tamper/rollback, exact schema migration and
process loss before/after evidence persistence/checkpoint/custody. Existing
funding, claim, payout/refund, waiver and child scenarios remain regression gates.

## Delivery boundary

Deliver reviewed Rust/store/verifier integration, independent verification,
private-chain crash evidence, source-bound command results, updated roadmap and a
clean local commit. This does not claim independent administrative operators,
public finality, full Finding backing, W1/verified-fix, hosted activation, a new
formal proof or a fuzz campaign. The next operator gate must use separately
administered keys and services, not merely additional processes on this host.
