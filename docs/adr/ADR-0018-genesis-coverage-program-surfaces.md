# ADR-0018: Genesis Coverage Program Surfaces (Royalty Right, Procurement List, Reliability Epoch, Operator Seat, Clearing Fee)

- Status: Proposed (research spike; see
  `docs/research/cognition-market/GENESIS-PROGRAM.md` and
  `docs/research/cognition-market/GENESIS-ARCHITECTURE.md` for the full analysis
  this ADR compresses)
- Decision owner: economy and settlement lane (with governance and trust lanes
  for seats and the reliability feed)
- Related: ADR-0017 (finding artifacts, reveal-as-governed-call), ADR-0015
  (non-discretionary escrow posture and the deferred D4 recipient allowlist),
  ADR-0016 (authoritative spend contract), `spec/PROTOCOL.md` 6.4.x (signed-
  artifact families)

## Context

The cognition market (ADR-0017) has a cold-start problem: buyer willingness-to-
pay is increasing in coverage, coverage needs sellers, sellers need paying
buyers. The Genesis Coverage Program bootstraps supply (coverage), security
(audits), and operations (clearing) ahead of organic demand, without a token, on
a bounded treasury, consortium-first. It pays exactly three things: money from a
bounded pre-funded subsidy pool, royalty rights on future clearing fees, and
position (reputation, coverage share, capped operator seats).

The program needs four new signed surfaces. Verification against the current
surface (pre-#974 main; PR #974 is unmerged, GENESIS-PROGRAM section 0)
established that none of the four can be assembled from existing primitives
without new wire surface:

- No royalty / revenue-share / fee-split primitive exists anywhere (empty grep
  across crates and contracts). Settle moves value only single-beneficiary
  (`chio-settle/src/evm/prepare.rs:1027`) or one-shot slash-split
  (`src/evm/prepare.rs:971-1020`).
- No query telemetry, demand artifact, or commit-to-query privacy layer exists;
  listing search is stateless and `recent_receipts_volume` is supply-side self-
  reported (`chio-listing/src/discovery.rs:68`).
- The revocation oracle is set-membership only and cannot carry a per-key numeric
  `r` (`chio-revocation-oracle/src/sparse_merkle.rs:89-97`).
- No signed operator-roster-with-roles or capped-seat primitive exists; the
  `RosterPolicy` is unsigned config (`chio-control-plane/src/trust_control/capital_and_liability/liability.rs:11`)
  and its referenced anchor type (`AdjudicationJurisdictionReceipt`) exists
  only crate-internal (`pub(super)`,
  `chio-trust-market-context/src/artifacts.rs:239`), unverifiable at the
  consumption site.

## Decision

### D1. Four new signed artifacts, one new leaf crate, additive registration

The program adds `chio.genesis.procurement-list.v1`,
`chio.genesis.royalty-right.v1`, `chio.genesis.reliability-epoch.v1`, and
`chio.genesis.operator-seat.v1`, defined in a new leaf crate
`crates/economy/chio-genesis` (pure types plus fail-closed validators, no
storage), each registered at its OWNING milestone (GENESIS-PLAN G1b, G2, G3,
G4 respectively) via the existing four-place registration (JSON schema,
`registry.json`, `SIGNED_ARTIFACT_SCHEMA_SPECS`, PROTOCOL.md), never ahead of
it; the crate's types may exist earlier (G1a) with no registration. All four
are `deny_unknown_fields` and sign INLINE per the chio-finding convention (a
`signature` field over the canonical body with `signature` cleared, using the
canonical signing pair the envelope also uses,
`chio-core-types/src/receipt/lineage.rs:420-434`); the `SignedExportEnvelope`
WRAPPER is explicitly not used, because a registered schema must validate the
signed artifact exactly as serialized (the M0/M1 plan's settled rationale for
the finding family). No new registry, venue, escrow contract, or settlement
rail is introduced.

### D2. The royalty right is a signed forward-flow split table, non-transferable

A royalty right (`chio.genesis.royalty-right.v1`) is a signed CLAIM on a
fraction (`share_bps`) of the D7 CLEARING FEE (net of operator spread) that
future hits to a finding generate, granted by the venue governance charter,
keyed by `finding_id` only, with a published step-down schedule and a genesis
expiry. Rights mint at either genesis admission door (floor admission, or
royalty-only admission for classes the audit lane cannot verify). The right is
realized only once the D7 fee exists (G5) on the collection machinery the
finding-market milestones establish (M2 publication fee, M5 dispute fee); until
then it accrues against a declared table with zero live flow.

Payment is FORWARD-FLOWING only: the fee split is a new fee on a new hit and
never claws back settled seller revenue (ADR-0015 immediate-release posture
unchanged). Payment rides the EXISTING settlement path: each royalty leg is an
ordinary single-beneficiary release, or a batched epoch settlement through the
exact-sum distribution shape generalized beyond bond-impair (D5). The right is
NON-TRANSFERABLE by construction (the beneficiary is bound in the artifact and
no transfer operation exists), with a CHANGE-OF-CONTROL LAPSE: validity is
conditioned on continuity of control of the beneficiary org, and change of
control lapses the right unless the charter re-grants it (key or org sale is
otherwise an untracked transfer channel). Off-protocol side-contracts on the
income stream are acknowledged as unpreventable; the operator pays only the
bound beneficiary, so a side-buyer holds unsecured counterparty risk with no
protocol recourse, which is deliberate hostility to a secondary market.
Non-transferability is normative, not a preference: a transferable right paying
a fee stream is a transferable financial reward unit, the token the program
forbids. Any future transferable profile is a separate ADR and out of scope
here. Royalty and seat shares are JOINTLY capped by the published genesis
carve-out cap (default 25 percent of the clearing fee) so the
security-self-funding inequality stays satisfiable (GENESIS-PROGRAM 9.1).

### D3. The reliability epoch (r feed) is a signed statistic, not a proof, and not the oracle

The public hit-reliability statistic `r` is published as
`chio.genesis.reliability-epoch.v1`: a signed, windowed aggregate carrying
`{ corpus, seller, guarantee_class, r_bps, n, decayed }` rows, computed as the
time-decayed audit-success rate (the `compute_reliability` math,
`chio-reputation/src/compare.rs:160`; crate-private today, so the builder
exports or re-derives it) stratified by guarantee class, over audit receipts,
following the `SignedPortableReputationSummary` WINDOWED-AGGREGATE pattern
(`chio-credentials/src/portable_reputation.rs:224`; its envelope is not used,
D1). It MUST NOT reuse the
revocation oracle's membership tree (which cannot carry a per-key value). It is
named "reliability epoch", not "feed", to avoid collision with the existing
`ReputationFeed` vocabulary (`chio-reputation/src/feed.rs`).

`r` is a STATISTIC buyers weight, never a proof (P10 / `ChioProofClaims`
discipline, ADR-0017 D3): it never upgrades a finding's evidence class. `n`
(sample size) is mandatory so low-sample `r` is visibly weak. Stratification by
`guarantee_class` is mandatory so a `metered_attested` `r` (not mechanically
verifiable) is never read as a `deterministic_replay` `r`.

### D4. Operator seats are capped, non-transferable position with a neutrality covenant

A genesis operator seat (`chio.genesis.operator-seat.v1`) is a signed grant from
the governance charter binding a vertical, an operator identity, a
`fee_share_bps` (realized only once collection exists), the F6 neutrality
covenant (ARCHITECTURE F6), a predeclared revocation rule, and a genesis expiry.
The per-vertical cap is a charter parameter enforced at issue time (the issuer
refuses to sign beyond the cap); there is no on-chain slot machine. Seats are
NON-TRANSFERABLE (bound to the operator identity; position, not a tradeable
unit), with the same CHANGE-OF-CONTROL LAPSE as royalty rights (D2): a sale of
the seated org lapses the seat unless the charter re-grants it, named as a
trigger beside `revocation_rule_ref`. Revocation on a neutrality violation
fires through the EXISTING levers: a
governance `Sanction`/`Freeze` case (`chio-governance/src/evaluation.rs:304-317`)
named by `revocation_rule_ref`, plus on-chain `deactivateOperator`
(`contracts/src/ChioIdentityRegistry.sol:89`). No new revocation authority is
created.

### D5. Settlement carries royalties by generalizing the exact-sum distribution, not by a new rail

The only multi-party split primitive today is bond-impair-only
(`bond_distribution_hash` / `validate_bond_impair_distribution`,
`chio-settle/src/evm/prepare.rs:971-1020`, at most 16 beneficiaries, exact-sum).
Batched royalty settlement generalizes THIS shape (same exact-sum, non-zero-
address, bounded-beneficiary invariants) beyond the impair action, as a thin
`chio-settle` extension reviewed with that lane's owner. No new value-movement
contract, no atomic swap, no kernel change. Single-leg royalties use the existing
single-beneficiary release unchanged. This keeps the program inside the ADR-0015
predeclared-terminal-state posture: a royalty leg is an ordinary release, and its
only terminal states remain release or refund.

### D6. The subsidy pool is off-chain operator-custodied; admission is the discipline

No treasury / pool / fund-balance primitive exists, and building an on-chain pool
that pays later-discovered recipients would be new contract surface the program
forbids. The subsidy pool is a bounded, pre-funded, OFF-CHAIN budget in the
settlement numeraire, custodied by the bonded, F6-neutral venue operator. Floor
custody rides the EXISTING escrow terminal states: each admitted floor is an
escrow (depositor = pool operator, beneficiary = seller, deadline = audit-window
end plus cadence margin) that RELEASES BY DEFAULT at window end via the
operator-signed path (`releaseWithSignature`,
`contracts/src/ChioEscrow.sol:199-228`; digest binds the admission receipt
hash, or a sampled passed audit's receipt hash for early release), with the
deadline refund returning the floor to the pool only when a SAMPLED audit
fails; junk stays negative-EV without per-floor audits because the floor is
capped at `kappa <= 0.5` of verified metered burn. No new custody primitive and
no third terminal state (ADR-0015 D2 posture unchanged). Floors are payable at
launch only for findings whose guarantee class the audit lane can mechanically
verify (`deterministic_replay`; the launch determinism rule, GENESIS-PROGRAM
4.1). The "buys inventory or security, never behavior" discipline lives in the
ADMISSION GATE (procurement-list descriptor match plus required guarantee class,
mode-A proof-of-burn, `BondBacked` slashable listing, audit sample), not in an
on-chain recipient allowlist. This inherits the same
operator-trust posture the program already accepts (T1/T3) and the same (prose-
level, not code-level) ADR-0015 D4 recipient discipline (see Consequences).

### D7. The clearing fee is a genesis-introduced fee category, and the royalty's denominator

The settled fee taxonomy (`OpenMarketFeeScheduleArtifact`: publication,
dispute, participation fees; MECHANISMS 6) contains NO per-clearing venue fee,
and the finding-market milestones build collection only for the publication
(M2) and dispute (M5) fees. The royalty (D2), the seat fee share (D4), and CCV
all denominate in a per-clearing fee; without this decision they would be
claims on a category nothing collects. D7 therefore INTRODUCES the clearing
fee: a small ad-valorem venue take on each finding purchase, collected at
reveal settlement by the mediating operator as an ordinary metered/settled
charge (the same machinery pattern M2 establishes for the publication fee),
with `operator_spread` as the operator-retained portion and the remainder the
splittable base for royalty and seat legs. It is a fee-schedule EXTENSION (a
new field family on the fee-schedule artifact or a sibling signed schedule),
not a new settlement rail; its owning milestone is G5 (landing together with
the CCV methodology that denominates in it); and it requires ratification by
the finding-market fee-schedule owners, recorded here as a cross-program
dependency, not assumed. Until D7 lands there is no clearing fee, no royalty
or seat live flow, and no CCV.

## Consequences

- Positive: the program reduces to four signed artifacts plus one thin,
  invariant-preserving settle generalization plus a metric, reusing every
  signing, governance, reputation, anchoring, and settlement primitive already
  ratified. No token, no new rail, no kernel change. The anti-token boundary is
  enforced structurally (all three durable rewards are non-transferable:
  royalties bound to a key, seats bound to an identity, position is reputation).
- Negative and honest:
  - The royalty and the seat fee share have ZERO live flow until the D7
    clearing fee lands (G5, on the M2/M5 collection machinery, after PR #974
    merges); both are signed claims against a declared table meanwhile, and
    the D7 fee itself needs finding-market ratification.
  - The royalty split trusts the operator to apply the signed table correctly; a
    mis-split is challengeable but the trust is real (an F6-neutrality
    dependency).
  - The subsidy pool is off-chain operator-custodied; there is no trustless on-
    chain pool, and ADR-0015 D4's recipient allowlist (which would constrain
    where pool and slash money flow) is prose, not code, today (its on-chain
    Follow-up A is deferred because `ChioBondVault` is immutable). The program
    does not close this; it records it.
  - The r statistic for `metered_attested` findings is not mechanically
    verifiable and remains a soft signal (the honest-cost-fabrication residual,
    THREAT-MODEL S2 / GENESIS-PROGRAM 9.3).
  - Audit top-ups pay only venue-ASSIGNED auditors under the joint
    `s + beta <= 0.8` bound (GENESIS-PROGRAM 4.2); the assignment lottery and
    the bound are what keep self-slash farming negative-EV, and both are
    published program parameters.
  - Procurement demand-sourcing and its privacy (k-anonymity over buyer clusters)
    are net-new; there is no existing telemetry or commit-to-query layer to lean
    on.

## Non-goals

No token or transferable reward unit. No new settlement rail or escrow contract.
No on-chain subsidy pool. No kernel change. No seat auction at launch (defers the
token-boundary question; a later profile only). No permissionless profile at
launch (Sybil resistance across the three mines leans on consortium identity). No
reuse of the revocation-oracle tree for the r statistic. No pay-per-listing and
no pay-per-volume emission (subsidies buy inventory or security only). No
promotion of ADR-0017's or ADR-0015's deferred items (the D4 recipient allowlist
stays deferred).
