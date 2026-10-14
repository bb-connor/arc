# Funded work claim escrow slice

This slice demonstrates one finalized allocation, one admitted W0 job, one
verifier-established claim and one reconciled payment, together with rejection,
refund, and an earned child claim that survives parent failure. Results are in
[claim escrow results](../../market/open-agent-work/execution/05-claim-escrow-results.md).

**Design inputs:** [F1 contract draft](../../market/open-agent-work/execution/02-contract-draft.md),
[escrow fit](../../market/open-agent-work/execution/01-escrow-fit.md),
[Q1-Q10 qualification](../../market/open-agent-work/05-qualification.md) and the
[funding counterexample slice](2026-09-14-open-agent-work.md).

The experimental contract, its scripts and the federated work example are not on
main. They are linked at the `archive/pr1173-head-20261014` tag, and contracts
remain under the no-mainnet freeze.

## Architecture

An experimental claim escrow sits beside the existing `ChioEscrow`, which it does
not modify. It funds immutable work terms, commits a timely result, arbitrates
through a pinned F1 verifier, and preserves accepted withdrawals. Native admission
connects to the rail only through a reviewed and qualified paper/Security M4
integration.

The contract interface is `fund(terms) -> agreementId`,
`submitClaim(agreementId, commitment)`,
`recordDecision(agreementId, decisionDigest, accepted, verifierSignature)`,
`withdrawPayment(agreementId)` and `withdrawRefund(agreementId)`. Terms bind the
full agreement digest, payer, provider, verifier, token, amount and ordered
deadlines. Domain-bound signatures cover the submitted commitment and the full
decision digest.

The funding observer returns only a verified allocation tied to a pinned
deployment and code hash, a finalized block and the exact agreement, never a
boolean copied from the payer. A durable journal correlates agreement,
allocation, native operation, claim, decision and transaction identities, and
unknown broadcast state reconciles those same identities.

## Constraints

- Fail closed. Required-facet failures, unknown execution and occupied nonces are preserved.
- Signed JSON is RFC 8785; EVM authorizations are domain-separated.
- Local mock funds only: no live RPC, external keys, deployments or partner messages.
- Contract-only tests never qualify native execution.
- The price is 100 mock minor units with zero verifier and dispute fees; checker and gas costs are recorded separately.
- One output commitment per obligation, exact replay only, and separate funding for child liability.
- Accepted claims never expire for withdrawal; pending claims hold the resolution window.
- Monetary strings and checked sums cap at `2^53 - 1`, and conversion refuses loss.

## Components

### Monetary state machine

[`claim_model.py`](../../../examples/funded-work-model/claim_model.py) defines the
states Funded, Submitted, Payable, Paid, Rejected, TimedOut and Refunded, with
execution-unknown as independent metadata. Its tests and the
[bounded explorer](../../../examples/funded-work-model/claim_explorer.py) cover:

- exact submission replay and changed commitments;
- early and late decisions, and payment/refund exclusion;
- verifier outage, failed transfer, and accepted withdrawal after every deadline;
- two funding sources with a parent and child, where a parent refund cannot
  erase a child's Payable state and unfunded parent revenue cannot reserve a child.

Bounded action sequences and adversarial orderings, including duplicate decisions
and competing withdrawals, check conservation per funding source after every
step. A broken expiry transition is retained as a negative calibration. The
result is a bounded model result, not an unbounded proof.

### Development-chain escrow

The [experimental escrow](https://github.com/bb-connor/arc/blob/archive/pr1173-head-20261014/contracts/src/experimental/ChioWorkClaimEscrow.sol)
and its [bytecode tests](https://github.com/bb-connor/arc/blob/archive/pr1173-head-20261014/contracts/scripts/work-claim-escrow.test.mjs)
cover the following on a private in-process chain:

- exact received backing and every agreement binding;
- wrong payer, beneficiary, verifier, chain and contract;
- signature replay, duplicate and mutated commitments, and safe-integer bounds;
- deadline ordering: `submit_by` and `resolve_by` are inclusive, and timeout
  refunds come strictly after `refund_after`, never while a claim is pending;
- accepted withdrawal after expiry, a new-job pause and key rotation, with no
  buyer action;
- rejected refund, absent submission, verifier timeout, and failed-transfer
  retry without double accounting;
- competing payment/refund attempts, and model-generated traces checked against
  contract state and balance deltas.

A separately funded child reaches Payable, the parent expires and refunds, and
the child then withdraws.

### Paper/Security M4 integration

[`06-native-integration.md`](../../market/open-agent-work/execution/06-native-integration.md)
records the selected Security M4 local acceptance commit
`5d1a9ec0d900bd03ce55de903919d972be852d79` and how the paper behavior was
applied to it in bounded slices:

- old and new schema layouts are recorded, and research version 10 is never
  read as security version 10;
- caller custody is never fabricated for old rows;
- A2A goes through verified manifest construction;
- immutable unknown execution and original payment-release authority are preserved.

Local acceptance is separate from hosted serial, MSRV and combined-source
qualification.

### Native funded W0 obligation

The first admission slice uses the bounded private-chain confirmation profile in
[FUNDED.md](https://github.com/bb-connor/arc/blob/archive/pr1173-head-20261014/examples/federated-work/FUNDED.md).
Unfinalized, wrong-domain, reused or mismatched allocations deny before kernel
dispatch and before a new reservation, as does reuse under a changed request
identity or a fresh authority store. The native results are:

- [funding admission](../../market/open-agent-work/execution/17-native-funding-admission.md):
  verified private-chain funding, one original native operation and hold, actual
  W0 execution and crash recovery.
- [native Finding and settlement](../../market/open-agent-work/execution/19-native-finding-claim-settlement.md):
  retained native output, bounded custody, a signed asserted-class Finding,
  independent Python W0 verification, an observed claim and decision, and actual
  mock-token payout or refund on the original operation, hold and authorization.
  Worker SIGKILL recovery keeps those identities and exact transaction bytes.
- [native resolution and earned child](../../market/open-agent-work/execution/21-native-resolution-earned-child.md):
  explicit original contractual authority for rejection or timeout of a recorded
  positive capture, retaining consumed budget while completing a zero-paid
  resolution. A separately funded child earns an unpaid claim before the parent
  is killed, then collects after the parent refund using its retained authority.
  The parent remains outcome-unknown and is never replayed.
- [registered work and Finding acceptance](../../market/open-agent-work/execution/23-registered-work-finding-acceptance.md):
  the registered agreement, submission, dependency and decision profile, mapped
  through the existing Finding verifier. Unavailable or unsupported required
  facets cannot mint a financial decision.

The [recovery](../../market/open-agent-work/execution/10-recovery-review-results.md)
and [lifecycle recovery](../../market/open-agent-work/execution/12-lifecycle-recovery-results.md)
results add durable exact signed transactions and real crash recovery around
payment, submission, decision and refunds (16 W0 cases, 48 killed workers).
Earlier operations remain observable after later Paid or Refunded transitions.

## Open requirements

The one-host private-chain witness does not close the wider requirements:

- the general registered-artifact and full Finding-facet mapping, including
  Finding backing and commerce roles;
- public-chain finality;
- the funding observer and operation correlation over existing settlement proofs
  at full scope;
- disclosure, key and manifest substitution, capacity exhaustion (new work is
  refused before the 64-operation retention ceiling) and unknown-payment
  successor regressions;
- independent operators and sustained retention.

No result here claims independent companies, real settlement finality or H1-H5.
The slice completes when one reviewable candidate demonstrates success,
rejection or refund, uncertainty reconciliation and a still-unpaid earned child
claim surviving parent failure, with direct authoritative evidence. W1,
independent implementation and sustained retention follow before the external trial.
