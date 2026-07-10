# WS6 Design: Agent credit bureau (portable financial passports)

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: none hard; WS10 anomaly findings and WS1 settlement telemetry enrich the corpus
- Claim track: implementation + external evidence (cross-issuer exchange requires a partner pilot before any cross-org trust claim)
- Branch: chio/ws6-credit-bureau off main

## Goal

Extend the agent passport with a portable financial-credential family so that an
agent's economic history (credit standing, exposure, settlement reliability,
premium and loss history) travels across organizations as signed, individually
verifiable, selectively disclosable Verifiable Credentials, and feeds a
receiving organization's underwriting evidence path under the existing
imported-signal discipline. The mechanism ships within the bounded release
posture; any claim that financial standing is trusted across two real
organizations is gated on a partner pilot.

## Context

The passport today proves behavioral standing only. `AgentPassport.credentials`
is a homogeneous `Vec<ReputationCredential>`
(`crates/trust/chio-credentials/src/passport.rs:6`), each credential carrying a
`LocalReputationScorecard` in its subject
(`crates/trust/chio-credentials/src/artifact.rs:281-321`), where that scorecard
is the eight-dimension reputation model
(`crates/trust/chio-reputation/src/model.rs:265-279`). Credentials are signed
with Ed25519 over canonical JSON and issued by the home authority
(`issue_reputation_credential`,
`crates/trust/chio-credentials/src/challenge.rs:119-183`); the passport is an
unsigned bundle of those signed credentials
(`build_agent_passport`, `challenge.rs:226-269`). Presentation filters the
bundle by issuer without invalidating remaining signatures
(`present_agent_passport`, `challenge.rs:341-362`) and evaluation runs a
`PassportVerifierPolicy` per credential
(`evaluate_agent_passport`, `challenge.rs:386-418`;
`crates/trust/chio-credentials/src/policy.rs:38-180`). OID4VCI issuance is
offered over the whole passport artifact (`spec/PROTOCOL.md:2871-2900`).

The economic layer already produces the local signed truth these credentials
would attest over: `CreditScorecardReport`
(`crates/economy/chio-credit/src/lib.rs:502-518`, schema at `:63`),
`ExposureLedgerReport` with per-currency positions
(`crates/economy/chio-credit/src/lib.rs:332-345`, positions at `:244-257`),
the credit loss lifecycle (`CreditLossLifecycleArtifact`,
`crates/economy/chio-credit/src/risk_reports.rs:171-203`), and premium quotes
inside signed underwriting decisions (`UnderwritingPremiumQuote`,
`crates/economy/chio-underwriting/src/decision.rs:206-215,229-232`). The
underwriting evidence path already models imported trust: `UnderwritingPolicyInput`
carries optional `reputation` evidence
(`crates/economy/chio-underwriting/src/lib.rs:354-372`) whose accepted imported
signals become `ImportedTrustDependency` findings
(`crates/platform/chio-control-plane/src/trust_control/underwriting_and_support/policy_support.rs:353-363`),
reusing the imported-trust discipline from
`crates/trust/chio-reputation/src/model.rs:281-365`. Cross-issuer aggregation
already exists and deliberately does not merge scores: a `CrossIssuerPortfolio`
lists independently verified passports and a signed `CrossIssuerTrustPack`
activates them per issuer without inventing a synthetic cross-issuer score
(`crates/trust/chio-credentials/src/cross_issuer.rs:26-35,78-93,449-591`;
`spec/PROTOCOL.md:2855-2863`).

## In scope

1. A financial-credential family `chio.fincred.<artifact>.v1`: five signed VC
   types (credit scorecard, exposure history, settlement reliability, premium
   history, loss history), each issued by the home authority over local signed
   evidence and each stamping an explicit evidence class.
2. A new pure contract crate `crates/economy/chio-fincred` holding the typed
   family payloads, the projections from signed economy reports into
   credentials, the financial verifier-policy vocabulary, and the underwriting
   projection. No I/O, `#![forbid(unsafe_code)]`, serde plus deterministic
   validation (shared invariant 4).
3. A generic, economy-agnostic financial-credential envelope added to
   `chio-credentials` as an optional `financial_credentials` vector on
   `AgentPassport`, so present, filter, challenge, and OID4VCI issuance apply
   unchanged.
4. A financial verifier policy `chio.fincred.verifier-policy.v1` (minimum
   settlement reliability, maximum open exposure against limit, loss-event
   thresholds, maximum credential age) evaluated per credential alongside the
   behavioral `PassportVerifierPolicy`.
5. An `UnderwritingImportedFinancialEvidence` struct added to
   `UnderwritingPolicyInput`, populated by the control plane from verified
   financial credentials, whose accepted imported signals emit the existing
   `UnderwritingReasonCode::ImportedTrustDependency`
   (`crates/economy/chio-underwriting/src/lib.rs:101,180`).
6. Cross-issuer aggregation v1 by reuse of the existing portfolio and trust-pack
   machinery: per-issuer activation, no score merging, no universal score.
7. JSON schemas under `spec/schemas/`, conformance coverage, and a
   `spec/PROTOCOL.md` 10.1 reconciliation note in the same phase (shared
   invariant 5).

## Out of scope (explicit cuts)

- BBS or zero-knowledge selective disclosure over individual claim fields.
  Field-level unlinkable proofs are named-future work
  (`docs/reference/AGENT_REPUTATION.md:898-923`); v1 selective disclosure is
  credential-granularity only.
- Any cross-organization trust claim. Cross-issuer exchange between two real
  organizations is external-evidence-gated on a partner pilot.
- A universal or merged credit score, and any credit-bureau-of-record posture
  (`spec/PROTOCOL.md:3443-3444`; `docs/reference/AGENT_REPUTATION.md:1003-1013`).
- Any value movement, custody, chain, or contract surface (shared invariant 6).
  WS6 issues and verifies evidence only.
- Writing settlement reconciliation state back into signed receipts. Reliability
  evidence derives from reconciliation reports, not receipts
  (`spec/PROTOCOL.md:944-947`).

## Design

### Credential family (schema ids chio.fincred.<artifact>.v1)

Each credential is a signed VC that mirrors the reputation envelope shape
(`@context`, `type: ["VerifiableCredential", "Chio<Family>Credential"]`,
`issuer` did:chio, `issuanceDate`, `expirationDate`, `credentialSubject`,
`evidence`, Ed25519 `proof`) but carries a financial payload and a digest-bound
reference to the local signed artifact it attests over. Monetary values are
`chio_core_types::capability::scope::MonetaryAmount`
(`crates/core/chio-core-types/src/capability/scope.rs:54`); ratios are integer
basis points; only genuine risk coefficients (the credit scorecard scores, which
are already `f64` at `crates/economy/chio-credit/src/lib.rs:497,446`) stay float
(shared invariant 2).

- `CreditScorecardCredential` (`chio.fincred.credit-scorecard.v1`): band,
  confidence, overall score, probationary status, and the imported-signal
  context, over a `SignedCreditScorecardReport`. Evidence class: observed.
- `ExposureHistoryCredential` (`chio.fincred.exposure-history.v1`): per-currency
  aggregates (governed max, reserved, settled, pending, failed, provisional
  loss, recovered) over a window, over a `SignedExposureLedgerReport`. Evidence
  class: observed.
- `SettlementReliabilityCredential` (`chio.fincred.settlement-reliability.v1`):
  on-time capture and settlement ratios in basis points, over settlement
  reconciliation reports. Evidence class: observed, and the credential says so.
  Settlement reconciliation state is intentionally not written back into signed
  receipts (`spec/PROTOCOL.md:944-947`), so reliability can never be verified
  class; the reconciliation evidence kind is already modeled as a distinct,
  non-receipt source (`crates/economy/chio-credit/src/lib.rs:200-207`).
- `PremiumHistoryCredential` (`chio.fincred.premium-history.v1`): premium quote
  aggregates over `SignedUnderwritingDecision` artifacts
  (`crates/economy/chio-underwriting/src/decision.rs:229-232`). Evidence class:
  verified at issuer level (folds only signed decision artifacts).
- `LossHistoryCredential` (`chio.fincred.loss-history.v1`): counts and
  outstanding amounts across the loss lifecycle event kinds
  (`crates/economy/chio-credit/src/risk_reports.rs:19-27`) over
  `SignedCreditLossLifecycle` artifacts. Evidence class: observed (delinquency
  detection depends on reconciliation state).

A credential's evidence class is the floor of the evidence classes of the signed
artifacts it folds; the class is stamped on the credential and never silently
upgraded (shared invariant 1).

### Issuance

Financial credentials are issued by the home authority exactly as reputation
credentials are: sign the canonical unsigned body with the authority keypair and
attach the proof (the `issue_reputation_credential` pattern,
`crates/trust/chio-credentials/src/challenge.rs:119-183`). They enter the bundle
as additional individually signed credentials. Because OID4VCI offers are made
over the existing passport artifact (`spec/PROTOCOL.md:2883-2900`), financial
credentials ride the existing issuance lane with no new transport.

### Verification and evaluation

`chio-credentials` verifies each financial-credential envelope with the same
checks used for reputation credentials (proof type and purpose, issuer DID and
verification method match, subject DID match, validity window, signature over
canonical JSON), treating the family payload as opaque canonical JSON that is
part of the signed body (the receipt-metadata "extensible JSON" precedent,
`spec/PROTOCOL.md:889`). `chio-fincred` then deserializes the payload per family
and evaluates it against `chio.fincred.verifier-policy.v1`, reusing the
fail-closed comparison style of `evaluate_credential_against_policy`
(`crates/trust/chio-credentials/src/policy.rs:182-201`): an unknown metric under
a policy minimum is a rejection, not a pass. The financial policy is a sibling of
`PassportVerifierPolicy` (`crates/trust/chio-credentials/src/passport.rs:419-461`)
rather than a widening of it, which keeps the trust crate free of economy
semantics; a verifier runs both and accepts only when both are satisfied.

Evaluation output feeds underwriting through a new optional
`imported_financial: Option<UnderwritingImportedFinancialEvidence>` on
`UnderwritingPolicyInput` (`crates/economy/chio-underwriting/src/lib.rs:362-372`),
defined in `chio-underwriting` (no dependency on `chio-fincred`) and shaped like
`UnderwritingReputationEvidence` with `imported_signal_count` and
`accepted_imported_signal_count`
(`crates/economy/chio-underwriting/src/lib.rs:221-231`). The control plane's
`build_underwriting_policy_input` populates it via `chio-fincred`, and
`derive_underwriting_signals` gains a branch mirroring the reputation branch: any
accepted imported financial signal emits one Guarded
`ImportedTrustDependency` signal
(`.../policy_support.rs:353-363`). The field is purely additive; the input schema
has no `deny_unknown_fields`, so old readers ignore it.

### Cross-issuer aggregation

Aggregation reuses the existing portfolio and trust-pack surface unchanged. A
holder bundles independently verified passports (each carrying its own financial
credentials) into a `CrossIssuerPortfolio`, and a verifier activates entries per
issuer with a signed `CrossIssuerTrustPack`
(`crates/trust/chio-credentials/src/cross_issuer.rs:449-591`). There is no score
merging and no universal score: activation is per entry and the financial policy
is applied per credential within each activated entry. This is the anti-claim
made concrete. Aggregation means the verifier's own policy decides per-issuer
trust, matching `spec/PROTOCOL.md:2855-2863` and the explicit gap at
`spec/PROTOCOL.md:3443-3444`.

### Privacy and selective disclosure

Because each financial credential is individually signed, a holder presents only
the credentials a relying party asks for and drops the rest without invalidating
remaining signatures (`present_agent_passport`,
`crates/trust/chio-credentials/src/challenge.rs:341-362`;
`docs/guides/ECONOMIC-LAYER.md:372-374`). The challenge issuer allowlist and
credential cap already bound what a presentation may carry
(`crates/trust/chio-credentials/src/presentation.rs:74-95`). The agent chooses
which credentials to include (`docs/reference/AGENT_REPUTATION.md:925-932`).
Field-level unlinkable disclosure (BBS, ZK over the receipt Merkle tree) stays
out of scope and is recorded above.

### Error handling (fail-closed)

Verification errors deny. A missing or mismatched evidence digest rejects; an
expired credential rejects; a subject-DID mismatch rejects; an unknown metric
under a policy minimum rejects. A `SettlementReliabilityCredential` that is not
stamped observed class rejects. Mixed-currency exposure yields null totals unless
`OracleConversionEvidence` is attached (shared invariants 2 and 3). Imported
financial credentials are never upgraded into the consumer's own observed or
verified evidence base; they remain attenuated imported signals under the
imported-trust discipline (`crates/trust/chio-reputation/src/model.rs:281-365`).

## Alternatives considered

1. Generic opaque financial payload in the passport (recommended) versus
   generalizing `AgentPassport.credentials` into a typed credential enum
   (`Reputation | Financial`). The enum is more type-safe but forces
   `chio-credentials` to depend on the economy crates or pulls economy types
   into the trust crate, inverting the current clean layering (no economy crate
   depends on `chio-credentials` today). Rejected for layering.
2. A separate `FinancialPassport` bundle parallel to `AgentPassport` with its own
   present, verify, and challenge functions. Rejected because it duplicates the
   presentation, challenge, and OID4VCI machinery instead of reusing it and
   splits the holder wallet into two bundles.
3. Merging financial signals into the reputation composite as a ninth scorecard
   dimension. Rejected: it violates the no-merge, no-universal-score anti-claim
   (`spec/PROTOCOL.md:3443-3444`) and conflates behavioral with financial
   standing.

Recommendation: alternative 1. Carry financial credentials inside `AgentPassport`
as an optional, individually signed, generic-payload vector, with the typed
interpretation, threshold policy, and underwriting projection in
`crates/economy/chio-fincred`.

## Claim and release framing

- Implementation (claimable within the bounded posture): the `chio.fincred.*`
  family, issuance in the passport bundle, verification plus the financial
  verifier policy, the underwriting imported-financial evidence projection, and
  per-issuer no-merge cross-issuer aggregation. All offline and local.
- External evidence (not claimable without a partner pilot): any statement that
  an agent's financial standing is trusted across organizations. Cross-issuer
  exchange between two real organizations requires a partner pilot first.
- Anti-claims carried in prose and disclaimers: not a universal credit score,
  not a credit bureau of record (that shape stays a market hypothesis,
  `docs/reference/AGENT_REPUTATION.md:1003-1013`), not settlement finality or
  custody, and settlement reliability is observed, not verified.

## Testing strategy

- Contract unit tests in `chio-fincred`: canonical-JSON round trips and byte
  stability per family; signature verify and reject; evidence-class floor
  computation; fail-closed on missing evidence digest, expiry, subject mismatch,
  unstamped reliability class, and unknown metric under a policy minimum.
- Proptest: threshold-evaluation monotonicity; mixed-currency exposure yields
  null totals without conversion evidence; basis-point arithmetic saturates and
  never wraps.
- Cross-issuer tests reusing `evaluate_cross_issuer_portfolio`: two-issuer
  financial bundle, one issuer rejected, assert the other still activates and no
  merged score appears.
- Underwriting golden test: accepted imported financial signals produce exactly
  one Guarded `ImportedTrustDependency` signal and never upgrade evidence class;
  absent or invalid credentials contribute nothing.
- Conformance: JSON schemas for each `chio.fincred.*.v1` under `spec/schemas/`,
  with insta snapshots using `sort_maps` for cross-environment key-order
  stability.
- Wire reconciliation: a passport with `financial_credentials` round-trips, and a
  passport without the field still verifies.

## Implementation phases

1. Contract crate and schemas. Create `crates/economy/chio-fincred` with the five
   family payloads and builders that project signed economy reports into
   credentials, add the optional generic `financial_credentials` envelope to
   `AgentPassport`, stamp evidence classes, and land JSON schemas plus
   conformance. Offline, no control-plane wiring.
2. Verification and financial verifier policy. Add `chio.fincred.verifier-policy.v1`
   and `evaluate_financial_credentials`, reuse present, filter, and challenge, and
   expose a CLI surface.
3. Underwriting integration. Add `UnderwritingImportedFinancialEvidence` to
   `chio-underwriting`, populate it in the control plane via `chio-fincred`, emit
   the `ImportedTrustDependency` signal, and add the golden tests.
4. Cross-issuer aggregation and the external-evidence gate. Confirm the existing
   portfolio and trust-pack surface carries financial bundles per issuer with no
   merge, and document the partner-pilot gate. No cross-org trust claim ships.

## Open questions

1. Wire compatibility. `AgentPassport` uses `deny_unknown_fields`
   (`crates/trust/chio-credentials/src/passport.rs:2`), so an old verifier rejects
   a new passport that carries `financial_credentials`. The `trust_tier` field set
   the precedent of adding an optional field for pre-launch single deployment
   (`passport.rs:12-16`). Recommend keeping `chio.agent-passport.v1` with the
   optional field and reconciling the `spec/PROTOCOL.md` 10.1 note in phase 1;
   the alternative is a `chio.agent-passport.v2` bump.
2. The brief asks to extend the `PassportVerifierPolicy` vocabulary; this design
   adds a sibling `chio.fincred.verifier-policy.v1` instead, to keep the trust
   crate economy-free. Confirm the sibling-policy approach is acceptable.
3. Carrying an opaque canonical-JSON payload inside `chio-credentials` leans on
   the receipt-metadata extensible-JSON precedent. Confirm this does not conflict
   with a project norm against opaque JSON in wire types; the typed-enum
   alternative carries the layering cost in open question 1.
4. Settlement reliability needs a bounded, deterministic on-time predicate over
   reconciliation reports (observed class), since receipts do not carry final
   settlement state. Define the window and predicate precisely in phase 1.
5. Whether to floor `PremiumHistoryCredential` to observed for uniformity or keep
   it verified at issuer level. Recommend keeping verified at issuer level while
   always attenuating cross-org.
6. Whether financial-credential issuance needs a distinct `spec/CHIO_LADDER.md`
   5.2 action class. It moves no value and is recommended to bind to the existing
   operator-authenticated passport-issuance authority (shared invariant 8);
   record if governance wants a separate class.
