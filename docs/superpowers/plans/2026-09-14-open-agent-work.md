# Open agent work: funding counterexample slice

This slice establishes, before any funded intercompany implementation, a
reproducible funding counterexample, an escrow-fit decision and a minimal
contract draft. Its execution package starts at the
[baseline report](../../market/open-agent-work/execution/00-baseline.md).

**Design inputs:** the [open agent work program](../../market/open-agent-work/README.md),
the [protocol design](../../market/open-agent-work/02-protocol.md), the
[program roadmap](../../market/open-agent-work/04-roadmap.md), the
[repository reconciliation](../../market/open-agent-work/08-repository-review.md)
(R01-R16, P40-P55) and the
[security sync review](../../market/open-agent-work/09-security-roadmap-sync-review.md).
The real pool ledger already has clone and rollback defenses; the small model
below is not a finding against it.

**Architecture:** the first executable model is independent of the kernel and
settlement runtime. It contrasts forkable payer-local balances with one
authoritative allocation state, then identifies the repository mechanisms that
implement that authority. It is an explanatory counterexample, not a distributed
settlement implementation.

## Constraints

- Fail closed: evaluation errors deny, and invalid policies reject at load time.
- Signed payloads are canonical JSON (RFC 8785).
- No live funds, deployment, partner communication or change to existing escrow semantics.
- The unsigned Python model objects are not wire artifacts or signed funding proofs.
- Existing escrow capabilities receive credit; a missing example integration is not a new cryptographic result.

## Deliverables

### Baseline

[`00-baseline.md`](../../market/open-agent-work/execution/00-baseline.md) records
the candidate source and included changes, the historical evidence used, the
environment and reproduction commands, fresh reproduction results with skipped
prerequisites, and the uncommitted or externally unqualified boundaries. It
consumes report 35 of the [September 2026 review](../../papers/review-2026-09/35-bounded-intercompany-subcontracts.md)
and the federated work example, which is linked at the
[source tag](https://github.com/bb-connor/arc/tree/archive/pr1173-head-20261014/examples/federated-work).

Native integration depends on a qualified Security M4 checkpoint. That
dependency remains open: the qualified checkpoint, the mapping of the research
store version against the security migration lineage, the verified A2A manifest
constructor, the caller start/report contract and the unknown-payment successor.
Custody is never backfilled, and unsupported profiles are never bypassed.

### Double-pledge model

[`examples/funded-work-model`](../../../examples/funded-work-model/README.md)
makes the distinction executable:

- `Claim(source, job, recipient, units)` is an immutable model claim.
- `AllocationAuthority(source, deposited)` exposes `reserve(claim) -> bool`,
  `available` and `claims`.
- Reservations are idempotent and bound to exact claims.

The tests show two local promises of 100 against one real source of 100, and
the authority accepting the first and refusing the second. Exact replay
reserves once; foreign sources and zero amounts refuse; every serial order
preserves `reserved + available`. The model has one trusted in-memory
authority, serial transitions, no monetary terminals, no signatures, no real
funding and no implementation-level concurrency proof. Signatures on the local
claims would add no backing.

The model is read beside the real signed allocation, store binding, domain lease
and rollback anchor, and the `finding_pool_ledger` suite in `chio-store-sqlite`
exercises those protections. Three results stay separate:

- the unsafe model counterexample;
- the qualified ledger behavior under its stated assumptions;
- the dishonest-operator threat that controls local enforcement and anchor
  state, which remains an untested hypothesis until executable.

### Escrow fit

[`01-escrow-fit.md`](../../market/open-agent-work/execution/01-escrow-fit.md)
maps each F1 requirement to existing escrow and settlement entry points. It
covers funding creation, agreement and beneficiary binding, claim certification,
one-time release, refund, key rotation, emergency pause and finality
observation, with the caller, binding, time ordering, supporting test and fit
decision for each. The deadline race, a valid result submitted before the work
cutoff but certified after the escrow deadline, is traced to the chain event
that preserves or loses eligibility. The decision records whether F1 needs an
adapter, a contract amendment or different pre-agreed timing, with the residual
verifier, registry and administrator assumptions of each option.

### Contract draft and comparison

[`02-contract-draft.md`](../../market/open-agent-work/execution/02-contract-draft.md)
and [`03-preregistration.md`](../../market/open-agent-work/execution/03-preregistration.md)
define the smallest bilateral contract and the first versioned comparison:

- existing bid, ask, acceptance and Finding types where they fit, with each new
  binding and its owning artifact;
- the P45/P47/P53 mappings of Finding facets and challenge roles, commerce,
  passport and risk claim ceilings, exact numeric encodings and retention horizons;
- a terminal matrix for accepted, rejected, unsubmitted, unknown and contested
  work, naming the decider, sufficient evidence, amounts, refund eligibility
  and retrievability;
- separate submission, dispute, claim and refund deadlines, with no design that
  needs an atomic database and chain transaction;
- H1-H5, C0-C3, sample selection, provisional thresholds, cost accounting and
  allowed baseline components, with any revision dated and justified before
  scored work;
- each Q1-Q10 property linked to a model obligation or a planned production
  test. The Python model covers only a fragment of Q2.

The next vertical slice, one finalized allocation, one admitted job, one
verifier-established claim and one reconciled payment with its rejection and
refund path, is the [claim escrow slice](2026-09-14-funded-work-claim-escrow.md).

## Boundary

The slice delivers the baseline, the executable counterexample, the escrow-fit
decision and the contract and comparison drafts. It advances P00-P09 and does
not complete M1 or G1. Later milestones remain in the
[program roadmap](../../market/open-agent-work/04-roadmap.md).
