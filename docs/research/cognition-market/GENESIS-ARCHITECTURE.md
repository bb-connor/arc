# Genesis Coverage Program Architecture

- Status: research draft (branch `research/genesis-program`)
- Basis: [GENESIS-PROGRAM.md](GENESIS-PROGRAM.md) (economics and mechanism),
  [ADR-0018](../../adr/ADR-0018-genesis-coverage-program-surfaces.md) (Proposed,
  the new wire surfaces), layered on the cognition-market
  [ARCHITECTURE.md](ARCHITECTURE.md)
- Discipline: paths cited for every claim about existing code; new surfaces are
  sketches and say so; every "reuse" row names the exact primitive reused and
  every "new" row justifies why nothing existing fits.

## 1. Why a sibling file, not an ARCHITECTURE.md extension

The cognition-market `ARCHITECTURE.md` is 956 lines and under active #1025
review (seven rounds). The Genesis surfaces are a distinct LAYER: a bootstrap
program that consumes the finding market rather than changing it. Keeping them
in a sibling file (a) leaves #1025's architecture byte-stable while its review
continues, (b) lets the Genesis architecture be reviewed as a stacked change,
and (c) matches the program boundary (the finding market can ship without the
Genesis program; the Genesis program cannot ship without the finding market).
Cross-references into `ARCHITECTURE.md` are by section number and are exact.

## 2. Reuse-first inventory (what the surface already provides)

Established during orientation (confidence: high for every path). The Genesis
program reuses these unchanged:

| Need | Existing primitive | Path |
|---|---|---|
| Signed artifact envelope | `SignedExportEnvelope<T>` (canonical JSON, Ed25519) | `chio-core-types/src/receipt/lineage.rs:407` |
| Signed numeric aggregate over receipts (the r-feed template) | `SignedPortableReputationSummary` (`effective_score: f64`, `window`) | `chio-credentials/src/portable_reputation.rs:224` |
| Time-decayed reliability rate over integrity-gated receipts | `compute_reliability` / `ReliabilityMetrics` | `chio-reputation/src/compare.rs:160`, `src/model.rs:250` |
| Signed governance charter with an operator allowlist | `SignedGenericGovernanceCharter`, `allowed_listing_operator_ids` | `chio-governance/src/generic.rs:181`; `chio-open-market/src/fee_schedule.rs:32` |
| Role revocation lever | governance `Sanction`/`Freeze` (`blocks_admission`) | `chio-governance/src/generic.rs:20`, `src/evaluation.rs:304-317` |
| On-chain operator deactivation | `deactivateOperator(address) onlyAdmin` | `contracts/src/ChioIdentityRegistry.sol:89` |
| Step-down basis-point schedule idiom | `TIER_DISCOUNT_PER_HUNDRED: [u32; 4]` | `chio-appraisal/src/marketplace_pricing.rs:148` |
| Single-beneficiary settlement release | `prepare_dual_sign_release` (full), `ChioEscrow` | `chio-settle/src/evm/prepare.rs:1027`; `contracts/src/interfaces/IChioEscrow.sol:7` |
| Multi-party exact-sum distribution (slash-only today) | `bond_distribution_hash` / `validate_bond_impair_distribution` | `chio-settle/src/evm/prepare.rs:971-1020` |
| Epoch root signing/anchoring cadence (operator-cron) | `AnchorAutomationJob` + `assess_*` | `chio-anchor/src/automation.rs:35` |
| Decaying topic-keyed signal (procurement staleness idiom) | pheromone deposit/decay | `chio-pheromone/src/lib.rs` (deposit), `src/validation.rs:782` (`strength_at`) |
| Wash/related-party signal | `root_budget_holder` / `delegation_depth` on financial metadata | `chio-core-types/src/receipt/economics.rs:33` |
| Descriptor search / listing publication | `chio-listing` discovery + namespace-owner signature | `chio-listing/src/discovery.rs:291`, `src/util.rs:27` |

The Genesis program adds four new signed artifacts and one metric, all in a new
leaf crate `crates/economy/chio-genesis` (mirroring the `chio-finding` style:
pure types plus fail-closed validators, no storage, no I/O). New wire surface is
gated on [ADR-0018](../../adr/ADR-0018-genesis-coverage-program-surfaces.md).

## 3. New artifact data model

Schema ids proposed (registration path identical to ARCHITECTURE 7.1: JSON
schema under `spec/schemas/chio-genesis/v1/`, `spec/schemas/registry.json` row,
`SIGNED_ARTIFACT_SCHEMA_SPECS` row in `chio-core-types/src/signed_artifact.rs`,
PROTOCOL.md section). All register at their OWNING milestone, never ahead of it
(the #1025 M0 lesson: schemas ahead of their milestone are speculative public
surface).

| Schema | Kind | Owning milestone |
|---|---|---|
| `chio.genesis.procurement-list.v1` | signed demanded-descriptor list | G1 |
| `chio.genesis.royalty-right.v1` | signed forward-flow fee-split entry | G2 |
| `chio.finding.reliability-epoch.v1` | signed r statistic over audits | G3 |
| `chio.genesis.operator-seat.v1` | signed capped non-transferable seat | G4 |

### 3.1 `chio.genesis.procurement-list.v1` (Q3)

The demanded-descriptor list sellers mine against. NEW because verification found
no query telemetry, no demand artifact, and no commit-to-query privacy layer to
reuse (search is stateless; `recent_receipts_volume` is supply-side self-
reported, `chio-listing/src/discovery.rs:68`).

| Field | Type | Semantics |
|---|---|---|
| `schema` | string | `chio.genesis.procurement-list.v1` |
| `list_id` | string | content-addressed over the body with id/signature cleared |
| `governing_operator_id` | string | the venue governance operator that admits descriptors (NOT sellers, to defuse Goodhart, Q6) |
| `epoch` | u64 | monotone; each republish is a new epoch |
| `entries` | array | demanded descriptors, each `{ topic, context_sha256?, demand_bucket, coverage_state, floor_schedule_ref, admitted_at, stale_after }` |
| `k_anonymity_floor` | u32 | minimum distinct buyer clusters that must have queried a descriptor before it is listed (privacy gate; see 3.1.1) |
| `issued_at` / `expires_at` | u64 | validity window |
| `signature` | inline sig | over canonical body, verifiable against the governance charter signer |

`demand_bucket` is a coarse bucket (not a raw count) so the list does not leak
per-buyer intent. `coverage_state` is `uncovered` / `partial` / `saturated`,
computed from the finding index; a `saturated` descriptor stops paying a floor
(K5) and is a removal candidate.

**3.1.1 Sourcing demand without leaking buyer intent (net-new, Q3).** There is
no telemetry store and no query-privacy layer. The design:

- The venue governance operator, which already mediates queries (it runs the
  listing search surface, `chio-control-plane` `/v1/public/registry/listings/search`),
  aggregates query counts per descriptor across buyers. A descriptor is admitted
  to the list only after at least `k_anonymity_floor` DISTINCT buyer clusters
  (by `root_budget_holder`, `chio-core-types/src/receipt/economics.rs:33`) have
  queried it. Below `k`, the descriptor is not listed, so no single buyer's
  intent is exposed.
- The list publishes coarse `demand_bucket`s, never raw counts or per-buyer
  data. This is the leakage-ledger discipline (THREAT-MODEL X1/X2) applied to
  demand: the descriptor topic is already a deliberate leak in the finding
  market; the demand bucket adds at most one coarse bit of aggregate demand.
- The pheromone substrate is explicitly NOT used to carry raw demand: its
  deposits are origin-identified (`kernel_id` + `agent_passport_key_hash`,
  `chio-pheromone/src/lib.rs`), which would attach buyer identity to intent. The
  decaying-half-life IDIOM (`strength_at`, `src/validation.rs:782`) is reused for
  `stale_after` computation, but the carrier is the signed governance-published
  list, not a pheromone deposit.

**3.1.2 Governance, capture, staleness (Q3).** Descriptors are admitted by the
venue governance operator, never by sellers: a seller that could add descriptors
would manufacture demand for its own inventory (Goodhart; THREAT-MODEL G4). The
list is seller-read-only. Staleness: each entry has `stale_after`; entries decay
out on the half-life idiom, and `saturated` entries are removed so the pool stops
subsidizing solved descriptors. Removal is a new epoch (monotone), so the removal
is auditable.

### 3.2 `chio.genesis.royalty-right.v1` (Q2)

The forward-flow fee-split entry. NEW because no royalty / revenue-share /
fee-split primitive exists (verified: empty grep across crates and contracts). A
Proposed spec-shaped JSON schema stub for this artifact (deliberately located in
the research tree, unregistered, so the canonical schema manifest is untouched by
a research proposal) lives at
[genesis-schema-stubs/royalty-right.schema.json](genesis-schema-stubs/royalty-right.schema.json),
with a `.v999` negative fixture beside it; registration happens at G1a.

| Field | Type | Semantics |
|---|---|---|
| `schema` | string | `chio.genesis.royalty-right.v1` |
| `right_id` | string | content-addressed |
| `finding_id` | string | the finding whose hits generate the fee this right shares |
| `beneficiary` | pubkey | the genesis seller/auditor key; NON-transferable (bound here) |
| `share_bps` | u32 | basis points of the clearing fee (net of operator spread) this right receives |
| `step_down_schedule` | `[u32; N]` | published bps steps keyed by elapsed genesis time (the `TIER_DISCOUNT_PER_HUNDRED` idiom) |
| `granted_by` | string | the governance charter that granted it (the split authority) |
| `expires_at` | u64 | genesis clock `T_g`; after which the share is 0 |
| `signature` | inline sig | over canonical body, verifiable against `granted_by` charter signer |

**Enforcement (Q2, honest limits in GENESIS-PROGRAM 5).** The right is a CLAIM,
not a transfer. It is realized only at fee-collection time, which does not exist
until M2/M5 build collection (K1). When it exists:

- the operator collecting a clearing fee on a hit to `finding_id` computes
  `leg = fee_net_of_spread * effective_share_bps(now) / 10_000` and pays it to
  `beneficiary` as an ordinary single-beneficiary release
  (`chio-settle/src/evm/prepare.rs:1027`), OR batches accrued legs over an epoch
  through the exact-sum distribution shape generalized beyond impair
  (`bond_distribution_hash`, `src/evm/prepare.rs:971`; the generalization is an
  M-gated settle extension, GENESIS-PLAN G2);
- forward-only (K2): the fee split is a new fee on a new hit; it never claws back
  settled seller revenue;
- non-transferable by construction (the beneficiary is bound in the artifact and
  there is no transfer operation); this is the anti-token guarantee
  (GENESIS-PROGRAM 5);
- a mis-split is challengeable: the right and the fee receipt are both signed, so
  an operator that applies the wrong share produces evidence-invalid settlement
  (the challenge lane, ARCHITECTURE 4.3).

### 3.3 `chio.finding.reliability-epoch.v1` (the r feed, Q4)

The signed `r` statistic buyer pricing consumes. NEW, but a re-key of the
`SignedPortableReputationSummary` PATTERN rather than a novel construct; NOT a
reuse of the revocation oracle (which is set-membership only and cannot carry a
per-key value, `chio-revocation-oracle/src/sparse_merkle.rs:89-97`).

| Field | Type | Semantics |
|---|---|---|
| `schema` | string | `chio.finding.reliability-epoch.v1` |
| `epoch_id` | string | content-addressed |
| `feed_operator_id` | string | the reliability-oracle operator (a genesis vertical, Q5) |
| `epoch` | u64 | monotone |
| `window` | `AttestationWindow` | reuse `chio-credentials`/`artifact.rs:183` window shape |
| `rows` | array | each `{ corpus, seller, guarantee_class, r_bps, n, decayed }` |
| `signed_root` | ref | optional anchoring ref through the existing anchor lanes (K9) |
| `issued_at` | u64 | |
| `signature` | inline sig | `SignedExportEnvelope` shape |

`r_bps` is the time-decayed audit success rate for the `(corpus, seller,
guarantee_class)` triple, computed exactly as `compute_reliability`
(`chio-reputation/src/compare.rs:160`) but stratified by class and scoped to
audit receipts. `n` (sample size) is mandatory: a low-`n` `r` is visibly weak and
buyers discount it, which defuses audit-rate gaming (Q6). Stratification by
`guarantee_class` is load-bearing (K6): a `metered_attested` `r` must never be
read as a `deterministic_replay` `r`.

**Why a new artifact and not the reputation summary directly:** the reputation
summary is per-SUBJECT (`subject_key`), single composite; the r feed needs the
`(corpus, seller, guarantee_class)` stratification and a compact buyer-facing row
set, and it consumes AUDIT receipts specifically, not a subject's whole receipt
corpus. It is the same signing envelope and the same reliability math, re-keyed.

### 3.4 `chio.genesis.operator-seat.v1` (Q5)

The capped, non-transferable genesis seat. NEW because no seat / roster-with-
roles / capped-slot primitive exists (the `RosterPolicy` is unsigned config,
`chio-control-plane/.../liability.rs:11`, and its referenced
`AdjudicationJurisdictionReceipt` type is absent from the repo).

| Field | Type | Semantics |
|---|---|---|
| `schema` | string | `chio.genesis.operator-seat.v1` |
| `seat_id` | string | content-addressed |
| `vertical` | enum | `mediating_kernel` / `registry` / `status_oracle` / `reliability_oracle` |
| `operator_id` | string | the seated operator; NON-transferable (bound here) |
| `fee_share_bps` | u32 | basis points of the vertical's clearing fee (realized only once collection exists, K1) |
| `neutrality_covenant_ref` | string | the F6 neutrality obligation this seat accepts (K3) |
| `revocation_rule_ref` | string | predeclared decision rule that fires seat revocation on violation |
| `granted_by` | string | the governance charter that granted it (also carries the per-vertical cap) |
| `expires_at` | u64 | genesis clock |
| `signature` | inline sig | verifiable against `granted_by` |

**Cap enforcement:** the per-vertical cap is a governance parameter on the
charter; the charter issuer refuses to sign more than the cap's worth of seats
per vertical. This is the minimal non-token representation: a seat is position
(reward type c), not a tradeable unit. **Revocation:** `revocation_rule_ref`
names a governance `Sanction`/`Freeze` decision rule
(`chio-governance/src/evaluation.rs:304-317`); a neutrality violation enforced
through that case revokes the seat, and the on-chain settlement key is
deactivated via `deactivateOperator` (`contracts/src/ChioIdentityRegistry.sol:89`).
The F6 conflict surface (the escrow `operator` field, `IChioEscrow.sol:7`) is
exactly what the neutrality covenant governs.

## 4. The subsidy pool (Q1) is off-chain operator-custodied, not a new contract

Verification found no treasury / pool / fund-balance primitive; every money-
custody construct holds the poster's own funds and pays parties named at open
time (`ChioEscrow`, `ChioBondVault`, comptroller `reserve_units`). Building an
on-chain pool that pays later-discovered recipients would be new contract surface
that K7 forbids. The pool is therefore:

- an OFF-CHAIN, pre-funded budget in the settlement numeraire, custodied by the
  genesis venue operator (bonded, F6-neutral, Q5);
- paid out per admitted floor as an ordinary receipt-backed transfer on the
  existing single-beneficiary release path;
- disciplined by the ADMISSION GATE (descriptor match, mode-A burn, audit
  sample), not by an on-chain recipient allowlist (which does not exist, K1/K10
  gap);
- audited from receipts: every floor payment is a settlement leg with a receipt,
  so pool outflow is reconstructable and the leading indicators (GENESIS-PROGRAM
  9.1) are computable.

This is an honest limit (the pool trusts the operator), recorded in GENESIS-
PROGRAM 9.4 and THREAT-MODEL (G-series). It is the same trust posture the wider
program already accepts for the venue operator (T1/T3).

## 5. CCV is a computed metric, not a wire artifact (Q8)

CCV (GENESIS-PROGRAM 7) is computed over settlement receipts, not stored as a
signed good:

```
CCV = sum over arm's-length clearings of (clearing fee net of operator spread),
      dedup by (finding_id, buyer_cluster),
      exclude related-party clusters (shared root_budget_holder / operator).
```

It reuses `root_budget_holder` / `delegation_depth`
(`chio-core-types/src/receipt/economics.rs:33`) for related-party detection (the
C1 wash signal) and is a reporting-surface computation, so it needs no new wire
schema, only a documented methodology and a control-plane read surface. The first
agent-to-agent trade is a public receipt-backed event labeled the genesis
demonstration (self-dealing, excluded from CCV); CCV counts from the first
external arm's-length clearing.

## 6. Kernel enforcement points: NONE new

The Genesis program adds no kernel enforcement obligation. The digest gate
(ARCHITECTURE 6) is the finding market's; the Genesis surfaces are all control-
plane and settlement artifacts plus a metric. This is deliberate: the program is
a bootstrap layer, and the invariant-dense kernel path (`validation.rs`) is
untouched. The only settlement-side change is the M-gated generalization of the
exact-sum distribution beyond impair (3.2), which is a `chio-settle` extension
reviewed with that lane's owner, not a kernel change.

## 7. Services and deployment (control-plane surfaces)

New control-plane surfaces follow the three-step pattern (ARCHITECTURE 8.1: path
const, route, handler), all ship-dark behind a cargo feature until qualified
(ARCHITECTURE 8.4):

- `GET/POST /v1/genesis/procurement-list` - publish (governance) and fetch the
  demanded-descriptor list.
- `GET /v1/findings/reliability/{feed}/epoch` - fetch the current signed
  reliability epoch.
- `POST /v1/genesis/seats/issue` and `GET /v1/genesis/seats` - seat issuance
  (governance) and enumeration.
- `GET /v1/genesis/ccv` - the computed CCV report (methodology-pinned).

Epoch ticking for the reliability feed and procurement-list republish run on
operator cron (K9; `AnchorAutomationJob` idiom), not a daemon.

CLI: a `chio genesis` family (`procurement`, `royalty`, `reliability`, `seat`,
`ccv`) following the documented clap pattern (ARCHITECTURE 8.3).

## 8. Crate-level integration map

| Crate | Change class | What |
|---|---|---|
| `crates/economy/chio-genesis` (NEW) | new leaf crate | the four artifact types + pure fail-closed validators; no storage; mirrors `chio-finding` style |
| `crates/core/chio-core-types` | extend (additive) | four schema-registry rows in `signed_artifact.rs`; reuse `AttestationWindow`, `MonetaryAmount` |
| `crates/trust/chio-reputation` | reuse | `compute_reliability` math consumed by the reliability-epoch builder (stratified wrapper) |
| `crates/economy/chio-settle` | extend (thin, M-gated) | generalize `bond_distribution_hash` beyond impair for batched royalty legs (G2); royalty-leg release preparation |
| `crates/economy/chio-open-market` | reuse | fee schedule + bond classes (the floor escrow and audit bond ride these) |
| `crates/trust/chio-governance` | reuse/extend | charter carries per-vertical seat caps + procurement admit authority; Sanction case revokes seats |
| `crates/platform/chio-control-plane` | extend | procurement / reliability-epoch / seat / CCV surfaces per section 7 |
| `crates/products/chio-cli` | extend | `chio genesis` family per section 7 |
| `crates/economy/chio-anchor` | reuse | reliability-epoch and procurement-list root anchoring via `AnchorAutomationJob` |
| `spec/PROTOCOL.md` | extend | genesis family section; explicit-gaps note (permissionless deferred) |

## 9. Instance profiles (consortium launch vs permissionless later)

| Dimension | Consortium (launch) | Permissionless (later) |
|---|---|---|
| Procurement admit authority | venue governance operator | federated governance + reputation gate |
| Audit-mining participants | consortium members | any bonded challenger |
| Operator seats | governance-granted, small cap | auction or reputation-gated (a later ADR; auction risks the token boundary and is out of scope now) |
| Subsidy pool custody | one bonded venue operator | multi-operator or on-chain fund (needs the deferred ADR-0015 Follow-up A allowlist, K1/K10) |
| r-feed trust | one reliability-oracle operator | anchored multi-operator with equivocation slashing |
| Sybil resistance | consortium membership (identity is gated) | bonds + reputation tiers only (harder; THREAT-MODEL G6) |

The permissionless column is a PROFILE, not the launch, and every cell that
hardens under it is flagged in the threat model. The launch profile leans on
consortium identity for Sybil resistance across all three mines, which is why
permissionless is deferred (GENESIS-PLAN, Q7).

## 10. Non-goals (restated)

No token or transferable reward unit (hard constraint 1). No new settlement rail
or escrow contract (K7). No on-chain subsidy pool (net-new custody avoided;
off-chain operator-custodied instead). No kernel change. No auction for seats at
launch (defers the token-boundary question). No permissionless profile at launch.
No reuse of the revocation oracle for the r statistic (it cannot carry values).
