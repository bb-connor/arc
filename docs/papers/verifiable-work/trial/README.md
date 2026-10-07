# Independent trial operator handoff

This package is prepared for a future partner. It contains no external results
and authorizes no deployment or payment. The complete experiment remains
[the September preregistration](../../../market/open-agent-work/06-independent-trial.md).
The [analysis contract](ANALYSIS.md) preserves its thresholds and denominators.
An [unsent invitation draft](INVITATION.md) is ready for the project owner to
adapt after selecting a prospective partner.

## What an implementer receives

Use a frozen checkout containing this paper and its hash inventory. Read these
documents in order, recording every clarification and supplied code:

1. [Protocol reading guide](../PROTOCOL.md): commitments, authority and outcomes.
2. [W0 artifact wire profile](../../../../examples/funded-work/PROFILE.md) and
   [positive and malformed vectors](../../../../examples/funded-work/parser-vectors.json).
   This is the exact artifact-only grammar. Implement parsing, canonicalization,
   signature checking, the provider, backing checks and recovery independently.
3. [Checker profile](../../../../examples/funded-work/checker-profile.json): the
   declared-authentication inventory and exact pinned checker bytes. Reusing
   public cryptographic libraries is permitted and must be disclosed.
4. [Allocation and decision vectors](../../../../contracts/scripts/fixtures/work-claim-vectors.json)
   and [escrow](../../../../contracts/src/experimental/ChioWorkClaimEscrow.sol):
   typed rail binding and actual transition rules.
5. [Native integration profile](../../../../examples/federated-work/FUNDED.md):
   a separate profile with native operation and local-authority bindings.
   Its concrete agreements differ from the artifact-only profile. Neither the
   conceptual paper tuple nor a successful artifact parser is native conformance.
6. [Ordinary alternative and ERC-8183 comparison](../evidence/erc8183/REPORT.md):
   full permission to match Chio using existing mechanisms.

The W0 checker inventories OpenAPI declarations. It cannot qualify the useful
source-repair economics hypothesis. Freeze a separate W1 contract and checker
after the unscored pilot; do not call existing W0 compatibility a W1 result.

## Before exchanging work

Copy [manifest.template.json](manifest.template.json) to a versioned trial
repository and fill every null field required by the selected stage. Each
operator confirms its administration boundary, keys, approved recipients,
selected local authority, stores, funding cap and recovery responsibility.
Public keys are recorded; private keys and real customer inputs are not part
of this package. Record any common administrator as shared control.

Require three core work operators, one newcomer, at least two independently
written provider implementations, and an acceptance verifier independent of
the parties it adjudicates. A smaller compatibility exercise may be useful
but cannot pass the full independence gate. Cross-border claims require the
original two-jurisdiction phase; none is inferred from hosting regions.

Qualify the chosen off-host authenticated endpoints, custody, observer/finality
rules, rollback protection, capacity and sandbox before scored work. The
paper's local integration logs do not pass that gate. Use the original
[Q1-Q10 qualification matrix](../../../market/open-agent-work/05-qualification.md),
including the adversary and recovery schedule, and record unsupported cases.
Do not disable local authority or replace finality with a cached balance to
make a pairing run.

First reproduce the local artifact in a scratch checkout using
[ARTIFACT.md](../ARTIFACT.md). Then run every supported independent implementation
pairing against the frozen positive and negative vectors. Stage A uses test
funds only. Record unsupported profiles as explicit denials, never fallbacks.

## Running and stopping

The original stages are A compatibility, B a 30-task unscored W1 pilot,
C a frozen held-out evaluation, D adversarial operation, E newcomer onboarding,
and F a separately authorized real-payment canary. Stage C provisionally uses
150 task instances with three repetitions per applicable arm, subject to a
pilot-based power and budget decision frozen before scoring. No trial budget
or stopping rule has been chosen on a future partner's behalf.

For each attempted task, copy [attempt.template.json](attempt.template.json).
Allocate an attempt ID before dispatch. Retain errors, cancellations, unavailable
dependencies and unused funds. Include all retries under the original purchase
identity. Store exact public evidence with SHA-256 and independently reconstruct
rail state; a provider's summary is not a funding-authority observation.

Execute the eight [handoff scenarios](../EXTERNAL-TRIAL.md#required-executions)
and the wider Q matrix. In the key failure case, leave the child earned but
uncollected, stop the intermediary, refund the parent, then collect the child.
Record all balances before and after. Also show verifier outage separately:
work performed without a recorded accepting decision may receive no payment.

Stop new work on an exposure violation, lost required custody, inconsistent
funding observations, unauthorized execution or a violated declared guarantee.
Preserve the original histories and earned claim access. Record time until
dependencies return separately from recovery time after they return. No
operator may edit databases or reset allocations invisibly to rescue a run.

## Returning evidence

Return the frozen manifest and revisions, every attempt record, exact command
logs and terminal exit statuses, build/source/dependency hashes, public signed
artifacts, authority observations, fault schedule and human-assistance diary.
Include semantic integration diffs and time logs for every arm and onboarding
exercise. List withheld evidence and the reason; do not fabricate a public
replacement. An independent reviewer must reconstruct each claim without
trusting the demonstration narrator.

Publish claim-specific judgments with confidence intervals and the strongest
baseline. Passing compatibility supports compatibility. Commercial usefulness,
lower integration effort and autonomous procurement value need their own
measured results. A negative result is a valid completion of this experiment.
