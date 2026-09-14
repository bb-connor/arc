# Open Agent Work: Funding Counterexample Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` to implement this plan task-by-task in an isolated workspace. Steps use checkbox (`- [ ]`) syntax for tracking. This handoff selects inline execution; it does not request subagent dispatch.

**Goal:** Produce a reproducible funding counterexample, an escrow-fit decision and a minimal contract draft before implementing funded intercompany work.

**Execution record (2026-09-14):** The bounded deliverables exist in the
[isolated execution package](../../market/open-agent-work/execution/00-baseline.md).
Six model tests, 38 existing pool tests and six new escrow characterizations
pass. The stronger timely-claim promise has a retained failing calibration.
Native integration awaits a qualified Security M4 checkpoint; its conditional
gate remains open below. The [next vertical-slice plan](2026-09-14-funded-work-claim-escrow.md)
uses that finding before native funded implementation. No milestone or release
completion is inferred from this handoff.

**Architecture:** Keep the first executable model independent of the kernel and settlement runtime. Contrast forkable payer-local balances with one authoritative allocation state, then identify the real repository mechanisms needed to implement that authority. The model is an explanatory counterexample, not a distributed settlement implementation.

**Tech Stack:** Python standard library, existing Rust examples and Solidity source inspection. Use the repository's pinned toolchains for any reproduction of existing binaries.

**Spec:** [Open agent work program](../../market/open-agent-work/README.md), [protocol design](../../market/open-agent-work/02-protocol.md) and [full roadmap](../../market/open-agent-work/04-roadmap.md).

**Repository reconciliation:** Read [R01-R16](../../market/open-agent-work/08-repository-review.md)
before execution. The approved whitepaper title is **Chio: A Peer-to-Peer
Economy of Verifiable Work**. P40-P55 extend the original roadmap's integration
requirements. In particular, the real pool ledger already has clone and
rollback defenses; the small model below is not a finding against that ledger.
Also read the [security sync review](../../market/open-agent-work/09-security-roadmap-sync-review.md).
It strengthens P40/P43/P44/P48-P55 without adding work-package IDs. Native
funded execution must use a reviewed paper/security integration candidate;
the independent funding model does not depend on completing that integration.

## Global Constraints

- Fail-closed: errors during evaluation deny access. Invalid policies reject at load time.
- Serialization: canonical JSON (RFC 8785) for all signed payloads.
- No em dashes in code, comments, or documentation. Use hyphens or parentheses.
- Preserve the current dirty checkout and the report-35 evidence inventory.
- No live funds, external deployment, partner communication or changes to existing escrow semantics in this first slice.
- Unsigned Python model objects below are not wire artifacts and must never be presented as signed funding proofs.
- Existing escrow capabilities receive credit; a missing example integration is not a new cryptographic result.

---

## Task 1: record a reproducible starting point

**Files:**

- Read: `docs/papers/review-2026-09/35-bounded-intercompany-subcontracts.md`.
- Read: `docs/papers/review-2026-09/evidence/35-bounded-intercompany-subcontracts/manifest.json`.
- Read: `examples/federated-work/README.md` and `SUBCONTRACT.md`.
- Read: `docs/market/open-agent-work/08-repository-review.md` and `08-workspace-inventory.json`.
- Read: `docs/market/open-agent-work/09-security-roadmap-sync-review.md` and `09-security-sync-evidence.json`.
- Create: `docs/market/open-agent-work/execution/00-baseline.md`.

**Interfaces:** Consumes the current checkout and retained evidence. Produces
a baseline report identifying source, environment, included changes and
reproduction commands. No executable API is introduced.

- [x] Read the three design documents linked in the header and the current local instructions.
- [x] Refresh P40's member/artifact/feature map from the candidate. Root-workspace tests do not select standalone `examples/federated-work`, `examples/composed-baseline` or `examples/outcome-ledger-comparison`.
- [ ] Refresh security PR #1117 and optional process PR #1131. Record the chosen Security M4 checkpoint, the independently checkpointed paper changes, and the isolated integration route. Preserve both active worktrees; do not merge legacy #1029 as a shortcut. Refresh completed; selecting the qualified M4 checkpoint and the actual integration candidate remains pending.
- [ ] Before native integration, map the version-10 research store versus security's migration lineage, verified A2A manifest constructor, caller start/report contract and unknown-payment successor. Do not backfill custody or bypass unsupported profiles. The current source map is recorded; implementing and qualifying the combined candidate is deferred until that checkpoint exists.
- [x] Record current source and worktree state with these read-only commands:

```bash
git rev-parse HEAD
git status --short
git worktree list --porcelain
git diff --stat
```

- [x] Use `superpowers:using-git-worktrees` at implementation time to prepare an isolated candidate. Inventory the required uncommitted research files explicitly; a worktree at HEAD alone does not contain them. Do not reset the source or copy unrelated changes into the candidate.
- [x] Record the baseline report using these exact sections:

```markdown
# Funded-work baseline
## Candidate source and included changes
## Historical evidence used
## Current environment and reproduction commands
## Fresh reproduction results and skipped prerequisites
## Uncommitted or externally unqualified boundaries
```

- [x] Run the existing example reproduction commands actually documented in its README against the candidate. Record their exact invocation and terminal results. Do not replace a failed reproduction with historical test counts.
- [x] Review the baseline diff separately from any new model code. Suggested commit subject after review: `docs: record funded-work research baseline`.

## Task 2: make the double-pledge distinction executable

**Files:**

- Create: `examples/funded-work-model/funding_model.py`.
- Create: `examples/funded-work-model/test_funding_model.py`.
- Create: `examples/funded-work-model/README.md`.
- Read: `crates/kernel/chio-kernel/src/finding_pool.rs`, `crates/kernel/chio-swarm-authority/src/finding_pool.rs`, `crates/platform/chio-store-sqlite/src/finding_pool_ledger.rs` and `rollback_generation.rs`.
- Test existing behavior: `crates/platform/chio-store-sqlite/tests/finding_pool_ledger.rs`.

**Interfaces:** `Claim(source: str, job: str, recipient: str, units: int)` is
an immutable model claim. `AllocationAuthority(source: str, deposited: int)`
exposes `reserve(claim: Claim) -> bool`, `available: int` and
`claims: dict[str, Claim]`. It consumes one source's fixed deposited balance.
It produces idempotent reservations bound to exact claims. It deliberately
models no signature, finality, payout, refund or concurrency primitive.

- [x] Create this failing test file before the implementation:

```python
import itertools
import unittest

from funding_model import AllocationAuthority, Claim


class FundingTests(unittest.TestCase):
    def test_local_forks_can_promise_more_than_the_real_source(self):
        local_views = [100, 100]
        offers = [Claim("s", "c", "C", 100), Claim("s", "d", "D", 100)]
        self.assertTrue(all(c.units <= v for c, v in zip(offers, local_views)))
        self.assertGreater(sum(c.units for c in offers), 100)

    def test_authority_rejects_the_second_incompatible_allocation(self):
        authority = AllocationAuthority("s", 100)
        self.assertTrue(authority.reserve(Claim("s", "c", "C", 100)))
        self.assertFalse(authority.reserve(Claim("s", "d", "D", 100)))
        self.assertEqual(authority.available, 0)

    def test_replay_is_exact_and_does_not_reserve_twice(self):
        authority = AllocationAuthority("s", 100)
        claim = Claim("s", "c", "C", 60)
        self.assertTrue(authority.reserve(claim))
        self.assertTrue(authority.reserve(claim))
        self.assertFalse(authority.reserve(Claim("s", "c", "D", 60)))
        self.assertFalse(authority.reserve(Claim("foreign", "x", "C", 1)))
        self.assertFalse(authority.reserve(Claim("s", "zero", "C", 0)))
        self.assertEqual(authority.available, 40)

    def test_all_serial_orders_preserve_reserved_plus_available(self):
        claims = [Claim("s", str(i), "C", n) for i, n in enumerate((1, 2, 3, 4))]
        for order in itertools.permutations(claims):
            authority = AllocationAuthority("s", 7)
            for claim in order:
                authority.reserve(claim)
                reserved = sum(c.units for c in authority.claims.values())
                self.assertEqual(reserved + authority.available, 7)
                self.assertGreaterEqual(authority.available, 0)


if __name__ == "__main__":
    unittest.main()
```

- [x] Run `python -m unittest discover -s examples/funded-work-model -p 'test_*.py' -v`. Expected before implementation: failure to import `funding_model`, not a silently skipped suite.
- [x] Create the minimal implementation:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class Claim:
    source: str
    job: str
    recipient: str
    units: int


class AllocationAuthority:
    def __init__(self, source: str, deposited: int):
        if not source or type(deposited) is not int or deposited < 0:
            raise ValueError("invalid model funding source")
        self.source = source
        self.available = deposited
        self.claims: dict[str, Claim] = {}

    def reserve(self, claim: Claim) -> bool:
        if (
            claim.source != self.source
            or not claim.job
            or not claim.recipient
            or type(claim.units) is not int
            or claim.units <= 0
        ):
            return False
        existing = self.claims.get(claim.job)
        if existing is not None:
            return existing == claim
        if claim.units > self.available:
            return False
        self.available -= claim.units
        self.claims[claim.job] = claim
        return True
```

- [x] Rerun the command. Expected: four passing tests. The first passes by demonstrating the unsafe local-only design; it does not assert that the current Chio escrow is vulnerable.
- [x] Write the README with the model interfaces, exact command, first-test counterexample and these limitations: one trusted in-memory authority, serial transitions, no monetary terminals, no signatures, no real funding, no implementation-level concurrency proof.
- [x] Add a trace table showing two local claims of 100 against one real source of 100, then the authority accepting the first and rejecting the second. Record why signatures on the local claims would not supply additional backing.
- [x] Compare the model with the real signed allocation, store binding, domain lease and rollback anchor. Read `cognition_market_sqlite_clone_cannot_reuse_the_store_binding`, `cognition_market_allocation_binds_one_concrete_store_across_deployments` and `cognition_market_authenticated_pool_restart_never_exceeds_signed_amount` before claiming a missing protection.
- [x] In the isolated qualified environment, list and run the existing pool suite:

```bash
cargo test --locked -p chio-store-sqlite --test finding_pool_ledger -- --list
cargo test --locked -p chio-store-sqlite --test finding_pool_ledger -- --test-threads=1
```

Expected: the named tests are present and the existing protections pass. The
test fixture uses `/dev/shm` for a separate-device anchor; satisfy that boundary
instead of weakening it. Record unavailable prerequisites as unqualified.

- [x] Write three separate results: unsafe model counterexample, qualified ledger behavior under its stated assumptions, and the stronger dishonest-operator threat including control of local enforcement and anchor state. If the stronger native attack is not yet executable, record it as an untested hypothesis rather than marking P01 complete.
- [x] Review this as a standalone explanatory artifact. Suggested commit subject: `test: model forked funding claims and exclusive allocation`.

## Task 3: determine whether existing escrow can enforce F1

**Files:**

- Read: `contracts/src/ChioEscrow.sol`, `contracts/src/interfaces/IChioEscrow.sol`, `contracts/src/ChioRootRegistry.sol` and `contracts/src/ChioIdentityRegistry.sol`.
- Read: `crates/economy/chio-settle/src/evm/prepare.rs`, `finalize.rs`, `types.rs` and `crates/economy/chio-web3/src/settlement_proof.rs`.
- Create: `docs/market/open-agent-work/execution/01-escrow-fit.md`.

**Interfaces:** Consumes the existing public contract methods and F1's required
transitions. Produces a fit table with exact caller, data, state, trust and
deadline requirements. It does not invent a new settlement API.

- [x] Locate the existing entry points:

```bash
rg -n 'function |deadline|consumedReceipt|operatorEpoch|refunded' contracts/src/ChioEscrow.sol
rg -n 'pub fn |pub async fn |finality|reorg|escrow' crates/economy/chio-settle/src/evm crates/economy/chio-web3/src/settlement_proof.rs
```

- [x] Read the bodies and their relevant tests. Fill a row for each of funding creation, agreement binding, beneficiary binding, claim certification, one-time release, refund, key rotation, emergency pause and finality observation.
- [x] Use columns `F1 requirement`, `existing entry point`, `caller/authority`, `enforced binding`, `time ordering`, `counterexample or supporting test`, and `fit decision`.
- [x] For the deadline race, trace a valid result submitted before the work cutoff but certified after the escrow deadline. Determine exactly which chain event preserves or loses eligibility. Do not assume a local verifier timestamp changes contract refund eligibility.
- [x] Record whether F1 requires an adapter, a contract amendment or different pre-agreed timing terms. State the residual verifier/registry/admin assumptions for every viable option.
- [x] Review the fit decision before any fund-moving implementation. Suggested commit subject: `docs: map funded-work requirements to escrow enforcement`.

## Task 4: freeze the contract and the first comparison

**Files:**

- Read: `docs/market/open-agent-work/01-thesis.md`, `02-protocol.md`, `05-qualification.md` and `06-independent-trial.md`.
- Create: `docs/market/open-agent-work/execution/02-contract-draft.md`.
- Create: `docs/market/open-agent-work/execution/03-preregistration.md`.

**Interfaces:** Consumes the model and escrow-fit decision. Produces a minimal
draft with exact monetary terminals, acceptance authority and unresolved research
questions, plus the first versioned comparison protocol. These are specification
deliverables, not claims of executable wire compatibility.

- [x] Define the smallest bilateral contract using the existing bid/ask/acceptance and Finding types where they fit. Enumerate each necessary new binding and its owning artifact.
- [x] Complete P45/P47/P53: map Finding facets/challenge roles, commerce/passport/risk claim ceilings, exact numeric encodings and retention horizons. Select local pool/swarm reuse and distinguish the post-dispatch settlement observer from the required funding-admission gate.
- [x] Write the terminal matrix for accepted, rejected, unsubmitted, unknown and contested work. Every row names who decides, what evidence is sufficient, service/fee amounts, refund eligibility and retrievability.
- [x] Specify separate work-submission, dispute, claim and refund deadlines consistent with Task 3. Reject any design requiring an unimplemented atomic database/chain transaction.
- [x] Record H1-H5, C0-C3, the trial sample-selection method, provisional thresholds, cost accounting and allowed baseline components exactly as adopted. Mark any justified revision with a date and reason before scored work begins.
- [x] Link every Q1-Q10 property to a model obligation or a planned production-level test. The small Python model covers only a fragment of Q2; it does not discharge the rest.
- [x] Review all four tasks' evidence and choose the next vertical slice: one finalized allocation, one admitted job, one verifier-established claim and one reconciled payment, plus its rejection/refund path. Use the escrow-fit result to write that slice's implementation plan before changing production code.
- [x] Suggested commit subject after review: `docs: freeze initial funded-work contract and comparison`.

## Completion boundary

This first-slice handoff is complete only when the baseline, executable
counterexample, escrow-fit decision and contract/comparison drafts exist with
fresh checks. It is progress on P00-P09, not automatic completion of M1 or G1.
It makes the most consequential design choices reviewable before a large
kernel, market or settlement change. Full milestones and later work remain in
the [program roadmap](../../market/open-agent-work/04-roadmap.md).
