# WS6 Design: Agent credit bureau (portable financial passports)

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS1 authenticated obligation/reconciliation range checkpoints for
  the settlement-reliability credential; other credential families land
  independently; no WS10 input edge is active in v1
- Claim track: implementation; external-evidence gate only (cross-issuer exchange
  requires a partner pilot before any cross-org trust claim)
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

The economic layer already produces local signed or authority-authenticated
evidence these credentials would summarize: `CreditScorecardReport`
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
   evidence and each stamping both its issuer-side source evidence class and its
   receiver-side imported evidence class.
2. Reuse-first implementation in `chio-credentials`, `chio-credit`, and
   `chio-underwriting`: credentials owns the versioned typed envelope, credit
   owns projections from signed reports, and underwriting owns the imported
   evidence input. A separate `chio-fincred` crate is allowed only if discovery
   proves these homes create a dependency cycle or unworkable feature boundary.
3. A schema-bound `FinancialCredentialEnvelope` carried by
   `chio.agent-passport.v2`, plus an explicit `VersionedAgentPassport` and
   `PassportCredentialV2` carrier. Its `family` discriminator selects one of
   five typed subject variants; arbitrary JSON payloads reject. Passport v2 is
   negotiated explicitly, so a v1 verifier never silently ignores financial
   credentials. The v2 challenge and presentation add credential-family and
   canonical credential-envelope-digest selectors; issuer-only filtering is insufficient when one
   issuer signs all five families.
4. A financial verifier policy `chio.fincred.verifier-policy.v1` (minimum
   settlement reliability, maximum open exposure against limit, loss-event
   thresholds, maximum credential age) evaluated per credential alongside the
   behavioral `PassportVerifierPolicy`.
5. An `UnderwritingImportedFinancialEvidence` struct added to
   `UnderwritingPolicyInput`, populated by the control plane from verified
   financial credentials, whose accepted imported signals emit the existing
   `UnderwritingReasonCode::ImportedTrustDependency`
   (`crates/economy/chio-underwriting/src/lib.rs:101,180`).
6. Cross-issuer aggregation through versioned portfolio and trust-pack adapters:
   per-issuer activation, no score merging, no universal score, and locally
   configured issuer and verifier trust anchors. A key submitted inside a
   credential or trust pack is never its own trust root.
7. JSON schemas under `spec/schemas/`, conformance coverage, and a
   `spec/PROTOCOL.md` 10.1 reconciliation note in the same phase (shared
   invariant 5).
8. Signed-schema admission in `spec/schemas/registry.json`,
   `spec/schemas/MANIFEST.sha256`, and `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, with a
   positive fixture and unknown-schema negative for each verifier-facing family.
   Public claims also require claim-registry and proof-manifest rows.

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
`evidence`, Ed25519 `proof`) but carries a typed financial subject and a
digest-bound reference to the local signed artifact it attests over. Each new
financial envelope also carries `issuer_key_epoch`; the verifier resolves
`(issuer, proof.verificationMethod, issuer_key_epoch)` through local trust before
checking the signature. The passport envelope is a tagged enum, not opaque JSON:
its `schema` and `family`
must select the same known subject variant before signature verification.
Monetary values are
`chio_core_types::capability::scope::MonetaryAmount`
(`crates/core/chio-core-types/src/capability/scope.rs:54`); ratios are integer
basis points; only genuine risk coefficients (the credit scorecard scores, which
are already `f64` at `crates/economy/chio-credit/src/lib.rs:497,446`) stay float
(shared invariant 2).

- `CreditScorecardCredential` (`chio.fincred.credit-scorecard.v1`): band,
  confidence, overall score, probationary status, and the imported-signal
  context, over a `SignedCreditScorecardReport`. The issuer-side class is the
  floor of the report dependencies and cannot exceed asserted when an imported
  signal influences the score.
- `ExposureHistoryCredential` (`chio.fincred.exposure-history.v1`): per-currency
  aggregates (governed max, reserved, settled, pending, failed, provisional
  loss, recovered) over a window, over a `SignedExposureLedgerReport`. The
  issuer computes the class floor from the bound receipts, reconciliation
  records, and any imported dependencies; it does not stamp observed merely
  because the aggregate was produced locally.
- `SettlementReliabilityCredential` (`chio.fincred.settlement-reliability.v1`):
  `on_time_count`, `obligation_count`, and their on-time terminal-settlement
  ratio in basis points over settlement reconciliation reports. Capture timing
  is not a separate v1 metric. The maximum issuer-side source class is observed,
  and issuance rejects if the
  required local reconciliation evidence is absent.
  Settlement reconciliation state is intentionally not written back into signed
  receipts (`spec/PROTOCOL.md:944-947`), so reliability can never be verified
  class; the reconciliation evidence kind is already modeled as a distinct,
  non-receipt source (`crates/economy/chio-credit/src/lib.rs:200-207`).
- `PremiumHistoryCredential` (`chio.fincred.premium-history.v1`): premium quote
  aggregates over `SignedUnderwritingDecision` artifacts
  (`crates/economy/chio-underwriting/src/decision.rs:229-232`). The issuer-side
  class may be verified only when every folded decision and its required
  evidence verifies; otherwise the dependency floor applies.
- `LossHistoryCredential` (`chio.fincred.loss-history.v1`): counts and
  outstanding amounts across the loss lifecycle event kinds
  (`crates/economy/chio-credit/src/risk_reports.rs:19-27`) over
  `SignedCreditLossLifecycle` artifacts. The maximum issuer-side source class
  is observed because delinquency detection depends on reconciliation state;
  lower-class dependencies lower the credential floor.

A credential carries two distinct fields. `source_evidence_class` is the floor
of the evidence classes of the issuer-local artifacts it folds.
`presentation_evidence_class` is always `asserted` when the credential crosses
an issuer boundary. Verifying the VC signature authenticates who made the claim;
it does not turn imported facts into locally observed or verified evidence. A
`CrossIssuerTrustPack` may admit the asserted signal under local policy but
cannot upgrade this class (shared invariant 1).

The issuer computes and verifies the source floor against the source artifacts
at issuance. A remote verifier cannot recompute that floor from digest strings
alone. A v2 presentation therefore either includes the bounded signed source
artifact bundle needed by the requested family or supplies resolvable references
accepted by the verifier's source policy. A bundle proves membership and source
class only; it never proves that omitted records do not exist. Any aggregate
whose meaning depends on absence or denominator completeness also carries an
authenticated boundary-complete range proof from the owning source checkpoint.
If the bundle/resolver or a required completeness proof is unavailable, the
verifier may reject or treat the issuer's floor and aggregate as asserted issuer
claims; it may not report either as independently recomputed. Even a fully
verified imported bundle remains presentation class `asserted` for
receiving-organization facts.

### Issuance

Financial credentials are issued by the home authority exactly as reputation
credentials are: sign the canonical unsigned body with the authority keypair and
attach the proof (the `issue_reputation_credential` pattern,
`crates/trust/chio-credentials/src/challenge.rs:119-183`). They enter the bundle
as additional individually signed credentials. OID4VCI offers advertise
`chio.agent-passport.v2` and the `financial_credentials_v1` feature explicitly.
A holder sends v2 only after that feature is negotiated; otherwise it sends a
v1 passport without financial credentials. This reuses the existing issuance
transport without relying on an old reader to ignore a new field
(`spec/PROTOCOL.md:2883-2900`).

The wire carrier is concrete and version-dispatched before payload
deserialization:

```rust
pub enum VersionedAgentPassport {
    V1(AgentPassport),
    V2(AgentPassportV2),
}

pub enum PassportCredentialV2 {
    Reputation(ReputationCredential),
    Financial(FinancialCredentialEnvelope),
}
```

`AgentPassportV2.credentials` is `Vec<PassportCredentialV2>`; the live
`AgentPassport.credentials: Vec<ReputationCredential>` remains the exact v1
type. The decoder reads and admits the top-level schema first, then invokes the
strict decoder for that version. Existing v1 APIs continue to accept only
`AgentPassport` and reject a v2 schema before field decoding. A named
`upgrade_v1_passport` conversion wraps each v1 credential as `Reputation` and
copies the remaining v1 fields. A named `try_downgrade_v2_passport` conversion
rejects any financial credential or v2-only selection state; it never drops
data. Generic `From`, untagged Serde fallback, and deserialize-v2-as-v1 paths are
forbidden.

The selector called `credential_ref_digest` is SHA-256 over the RFC 8785
canonical complete signed credential envelope, with a domain separator naming
the concrete reputation or financial family. It is not a caller label and does
not require adding a self-referential ID to the live v1 credential type. Holder
and verifier recompute it, each passport rejects duplicate digests, and the
challenge stores sorted unique digest selectors. Family plus digest must both
match when both are present; order, substitution, or an unknown digest rejects.

### Verification and evaluation

`chio-credentials` first resolves the envelope `schema` and `family` through the
signed-schema registry and deserializes the matching typed subject. Unknown
schema ids, unknown families, schema/family mismatches, and fields outside that
subject schema reject before signature evaluation. It then applies the same
checks used for reputation credentials (proof type and purpose, issuer DID and
verification method match, subject DID match, validity window, and signature
over canonical JSON). The financial policy evaluator then evaluates the typed
subject against `chio.fincred.verifier-policy.v1`, reusing the
fail-closed comparison style of `evaluate_credential_against_policy`
(`crates/trust/chio-credentials/src/policy.rs:182-201`): an unknown metric under
a policy minimum is a rejection, not a pass. The financial policy is a sibling of
`PassportVerifierPolicy` (`crates/trust/chio-credentials/src/passport.rs:419-461`)
rather than a widening of it; a verifier runs both and accepts only when both are
satisfied. Economy report projection stays in `chio-credit`, while the
wire-neutral typed credential contract and its verification stay in
`chio-credentials`.

Settlement reliability uses a fixed credential window `[window_start,
window_end)` over canonical obligations whose signed due time is in that window,
joined to their reconciliation sidecars at a source cutoff no earlier than
`window_end`. An obligation is on time only when its verified terminal settlement
timestamp is at or before its signed due time. Unresolved or failed obligations
remain in the denominator and are not on time. WS1's obligation and
reconciliation stores must expose the same authenticated checkpoint/range
contract used by corpus consumers: trusted source id and signer, anchor epoch,
checkpoint root/time, due-time and obligation-id index roots, inclusive ranges,
member counts derived from the committed indexes, and predecessor/successor
boundary proofs. The two ranges resolve at one cutoff, prove zero-or-one terminal
sidecar per obligation, and include absence proofs for unresolved obligations.
Missing, stale, gapped, duplicate, or mismatched range evidence prevents issuance
of a settlement-reliability credential. A bounded bundle alone cannot satisfy
this completeness contract. Require `on_time_count <= obligation_count` and
compute
`ratio_bps = floor(u128(on_time_count) * 10_000 / u128(obligation_count))`
with checked conversion. Verification recomputes it and rejects a stored-ratio
mismatch or overflow. The authenticated obligation count is the denominator
and must be nonzero. A complete empty window returns the unsigned projection
result `NoCredential(EmptyWindow)` and issues no VC; a signed reliability
credential with a zero denominator, a missing denominator, or a ratio when the
denominator is zero rejects. No default reliability ratio is inferred from an
empty window.

Evaluation output feeds underwriting through a new optional
`imported_financial: Option<UnderwritingImportedFinancialEvidence>` on
`UnderwritingPolicyInput` (`crates/economy/chio-underwriting/src/lib.rs:362-372`),
defined in `chio-underwriting` (no dependency on `chio-fincred`) and shaped like
`UnderwritingReputationEvidence` with `imported_signal_count` and
`accepted_imported_signal_count`
(`crates/economy/chio-underwriting/src/lib.rs:221-231`). The control plane's
`build_underwriting_policy_input` populates it from the verified typed result,
and
`derive_underwriting_signals` gains a branch mirroring the reputation branch: any
accepted imported financial signal emits one Guarded
`ImportedTrustDependency` signal
(`.../policy_support.rs:353-363`). This is an explicit underwriting schema and
version change. Compatibility is tested at the version boundary; it does not
depend on old readers silently ignoring the field.

### Cross-issuer aggregation

The live `CrossIssuerPortfolioEntry.passport` is an `AgentPassport`, and the live
trust-pack verifier verifies only the `signer_public_key` embedded in the pack
(`crates/trust/chio-credentials/src/cross_issuer.rs:9-24,276-303`). WS6 therefore
does not reuse that surface unchanged. `chio.cross-issuer-portfolio.v1` and its
existing evaluator remain v1-only. A new `chio.cross-issuer-portfolio.v2` entry
carries `VersionedAgentPassport`, and `chio.cross-issuer-trust-pack.v2` keeps the
existing per-entry policy semantics while identifying its signer by
`verifier_id`, `signer_key_id`, and `signer_key_epoch` rather than treating a
submitted public key as authority.

The verifier receives a locally configured `CrossIssuerTrustRegistry`. Its
issuer map resolves `(issuer_did, verification_method, key_epoch)` to a trusted
public key, and its verifier map resolves
`(verifier_id, signer_key_id, signer_key_epoch)` to a trusted public key. Both
maps must be nonempty for cross-issuer evaluation. Financial VC signatures are
checked with the issuer key resolved from this registry. Trust-pack signatures
are checked with the verifier key resolved from this registry. An embedded or
presented key, when retained for v1 diagnostics, must byte-match the resolved
key but is never a trust source. Unknown identity, missing or inactive epoch,
key mismatch, and a self-consistent signature from an unregistered key reject.
The v1 `verify_signed_cross_issuer_trust_pack` is hardened to require this local
registry too: it resolves `pack.body.verifier` to active local keys and treats
`pack.body.signer_public_key` only as a claimed key that must match one of them.
This hardening permits audit-time signature inspection only. Because the v1
body still carries caller-authored lifecycle, migration, profile, source, and
certification metadata, every production v1 evaluation returns
`UnsupportedLegacyCrossIssuerV1` and cannot activate an entry. No production
caller may retain the current evaluator or two-argument self-rooted verifier.
The evaluator interface is correspondingly explicit:

The registry also has a separate legacy-reputation map keyed by
`(issuer_did, verification_method)` whose entries pin public keys and explicit
issuance-validity intervals. A live `ReputationCredential`, which has no key
epoch, verifies only when exactly one locally pinned interval covers its
`issuanceDate`; DID-derived or embedded-key fallback is forbidden. A v2
portfolio rejects `VersionedAgentPassport::V1` entries entirely. A negotiated
`AgentPassportV2` may carry its `Reputation` arm only through this legacy map,
while every financial arm uses the epoch-qualified issuer map. The current
DID-derived passport verifier remains available only as explicitly named local
compatibility code and cannot activate a cross-issuer entry.

V2 also replaces the live caller-authored activation-metadata boundary. Every
trust-pack entry is a signed `EntryActivationDecisionV2` that binds the exact
passport digest, issuer, derived profile family and source kind, canonical
certification-reference set, lifecycle-evidence digest, migration-envelope
digests, decision, and reason. The verifier derives family, source, and
certification fields from verified signed credentials or locally configured
mappings and rejects a supplied mismatch. Lifecycle comes only from an
injected, locally configured `CrossIssuerLifecycleResolver` queried by exact
passport digest and issuer at evaluation time `now`. Its authenticated local
store result carries store generation and monotonic status version; the
verifier persists a per-passport high-water version and rejects unavailable,
stale, rolled-back, mismatched, or caller-supplied state. Cached `Active` cannot
survive a later suspension or revocation. Structural validation of an unsigned
portfolio value cannot establish `Active`. Every migration attester resolves through a local
active-key registry, and its signature binds the exact canonical migration
envelope digest. The trusted verifier signature covers the complete ordered
decision set, but it never substitutes for issuer, lifecycle, or migration
verification.

```rust
pub fn evaluate_cross_issuer_portfolio_v2(
    portfolio: &CrossIssuerPortfolioV2,
    now: u64,
    trust_pack: &SignedCrossIssuerTrustPackV2,
    trust: &CrossIssuerTrustRegistry,
) -> Result<CrossIssuerPortfolioEvaluation, CredentialError>;
```

There is no score merging and no universal score: activation is per entry and
the financial policy is applied per credential within each activated entry.
This is the anti-claim made concrete. Aggregation means locally anchored verifier
policy decides per-issuer trust, matching `spec/PROTOCOL.md:2855-2863` and the
explicit gap at `spec/PROTOCOL.md:3443-3444`.
Successful issuer-signature verification authenticates the issuer assertion; it
does not establish that the receiving organization observed or verified the
underlying facts. Every cross-issuer financial input therefore remains asserted
at the receiving boundary, including inputs admitted by a trust pack.

### Privacy and selective disclosure

Because each financial credential is individually signed, a holder presents only
the credentials a relying party asks for and drops the rest without invalidating
remaining signatures (`present_agent_passport`,
`crates/trust/chio-credentials/src/challenge.rs:341-362`;
`docs/guides/ECONOMIC-LAYER.md:372-374`). The challenge issuer allowlist and
credential cap already bound what a presentation may carry
(`crates/trust/chio-credentials/src/presentation.rs:74-95`). The agent chooses
which credentials to include (`docs/reference/AGENT_REPUTATION.md:925-932`). V2
extends the signed challenge with allowed and required financial family ids and
optional `credential_ref_digest` values, and the verifier checks the response satisfies that
selection without extras. A v1 issuer filter is not claimed as family-selective
disclosure.
Field-level unlinkable disclosure (BBS, ZK over the receipt Merkle tree) stays
out of scope and is recorded above.

### Error handling (fail-closed)

Verification errors deny. A missing or mismatched evidence digest rejects; an
expired credential rejects; a subject-DID mismatch rejects; an unknown metric
under a policy minimum rejects. A claimed source class above the recomputed
dependency floor rejects when the required source bundle or resolver is present;
without it, policy either rejects or preserves the field as an asserted issuer
claim. A `SettlementReliabilityCredential` without the
required observed reconciliation basis rejects. An unknown passport version, an
unnegotiated v2 passport, an unknown signed schema, or a schema/family mismatch
rejects. A zero-denominator settlement window issues no credential, and any
signed reliability credential claiming a zero denominator rejects. Missing local
issuer or verifier trust configuration, an unknown identity or key epoch, an
embedded-key mismatch, or a signature made by an unregistered self-selected key
rejects before portfolio policy evaluation. A missing or ambiguous legacy
issuance interval, unsigned lifecycle, untrusted migration attester, or
activation-metadata mismatch also rejects before policy evaluation. Mixed-currency exposure yields null
totals unless
`OracleConversionEvidence` is attached (shared invariants 2 and 3). Imported
financial credentials are never upgraded into the consumer's own observed or
verified evidence base; their presentation class remains asserted under the
imported-trust discipline (`crates/trust/chio-reputation/src/model.rs:281-365`).

## Alternatives considered

1. Generic opaque financial payload in the passport versus a wire-neutral typed
   credential enum (`Reputation | Financial`). Opaque JSON would let an
   authenticated issuer smuggle an unrecognized semantic shape through generic
   signature checks. Rejected. The selected enum keeps only schema-bound
   credential subjects in `chio-credentials`; economy report projections remain
   in their existing economy crates, so no economy dependency enters the trust
   crate.
2. A separate `FinancialPassport` bundle parallel to `AgentPassport` with its own
   present, verify, and challenge functions. Rejected because it duplicates the
   presentation, challenge, and OID4VCI machinery instead of reusing it and
   splits the holder wallet into two bundles.
3. Merging financial signals into the reputation composite as a ninth scorecard
   dimension. Rejected: it violates the no-merge, no-universal-score anti-claim
   (`spec/PROTOCOL.md:3443-3444`) and conflates behavioral with financial
   standing.

Recommendation: carry typed, individually signed financial credentials in the
explicitly negotiated `chio.agent-passport.v2`. Implement the wire contract and
verification in `chio-credentials`, report projections in `chio-credit`, and
the imported-evidence projection in `chio-underwriting`; extract a new crate
only if implementation discovery proves a dependency boundary requires one.

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
  custody, and no imported financial fact is observed or verified by the
  receiving organization merely because its issuer signature verifies.

## Testing strategy

- Contract unit tests in `chio-credentials`: canonical-JSON round trips and byte
  stability per family; signature verify and reject; evidence-class floor
  computation; fail-closed on missing evidence digest, expiry, subject mismatch,
  unstamped reliability class, unknown metric under a policy minimum, unknown
  schema, and schema/family mismatch.
- Presentation tests: two credentials from one issuer but different families;
  family/digest selection returns only the requested credential, rejects a missing
  required family and unrequested extras, and v1 issuer-only filtering is never
  reported as family-selective.
- Source-floor tests: bundled and resolver-backed artifacts recompute the floor;
  a digest-only remote presentation remains asserted or rejects by policy; a
  forged floor above any dependency rejects. Settlement reliability additionally
  requires same-cutoff authenticated obligation and reconciliation range proofs;
  omitted failed or unresolved obligations, missing absence proofs, and boundary
  gaps all reject issuance. A complete zero-obligation range returns
  `NoCredential(EmptyWindow)`; zero or missing denominators in a signed credential
  reject. Ratio fixtures prove exact floor division, require
  `on_time_count <= obligation_count`, and reject a stored bps value that differs
  from checked `on_time_count * 10_000 / obligation_count` recomputation.
- Proptest: threshold-evaluation monotonicity; mixed-currency exposure yields
  null totals without conversion evidence; basis-point arithmetic uses checked
  operations and rejects overflow.
- Cross-issuer tests cover a two-issuer v2 financial bundle, one issuer rejected,
  the other still activated, and no merged score. Registry negatives cover empty
  local trust, unknown issuer or verifier, inactive epoch, key-id mismatch,
  embedded-key substitution, and a self-consistent trust pack signed by an
  attacker-selected unregistered key. The legacy v1 evaluator cannot activate
  any production entry, even with a locally recognized pack signature. V2 rejects a v1
  passport entry, overlapping or absent legacy-reputation key intervals,
  DID-derived fallback, unsigned lifecycle substitution, caller-modified family,
  source kind, or certification refs, and migration signatures from embedded or
  unregistered attesters. Lifecycle tests suspend or revoke after an earlier
  `Active` result and prove stale replay, store-generation rollback, and resolver
  outage all deny.
- Underwriting golden test: accepted imported financial signals produce exactly
  one Guarded `ImportedTrustDependency` signal and never upgrade evidence class;
  absent or invalid credentials contribute nothing.
- Conformance: JSON schemas for each `chio.fincred.*.v1` under `spec/schemas/`,
  with insta snapshots using `sort_maps` for cross-environment key-order
  stability.
- Wire reconciliation: negotiated v2 with `financial_credentials` round-trips;
  v1 without the field still verifies; v1 with the field and unnegotiated v2
  both reject. Explicit v1-to-v2 conversion preserves every credential and field;
  v2-to-v1 rejects any financial credential or v2-only selection state. The live
  v1 APIs reject v2 directly rather than silently dropping fields.
- Signed-schema gates: registry, hash manifest, known-schema allowlist, positive
  fixtures, unknown-schema negatives, and claim/proof manifest consistency.

## Implementation phases

1. Typed contract and schemas. Add `VersionedAgentPassport`, `AgentPassportV2`,
   `PassportCredentialV2`, strict schema-first dispatch, explicit lossless v1
   upgrade and fail-closed v2 downgrade, and the five typed subjects to
   `chio-credentials`. Add report-to-subject projections beside their existing
   signed reports in `chio-credit`, add v2 family/envelope-digest challenge selectors and
   bounded source bundles or resolver references, consume the WS1 Phase 3
   authenticated due-time/obligation/reconciliation checkpoint contract and
   nonzero denominator required by settlement reliability, stamp both evidence
   classes, and land JSON
   schemas plus every signed-schema admission gate. Offline, no control-plane
   wiring. Settlement-reliability projection and issuance remain hard-disabled
   unless the store reports that exact proof substrate ready and verification of
   a fresh same-cutoff proof succeeds. Extract a separate crate only if a
   demonstrated dependency cycle requires it.
2. Verification and financial verifier policy. Define and land the signed
   `SignedCrossIssuerTrustPackV2` body, envelope, schema, and pure verifier
   contract plus `EntryActivationDecisionV2`. Add the locally configured
   epoch-qualified issuer/verifier maps, legacy-reputation interval map,
   migration-attester registry, and `CrossIssuerLifecycleResolver` contract;
   derive every activation-relevant metadata field and digest-bind every
   migration. Harden v1 signature inspection but make v1 production activation
   unconditionally unsupported. The pure v2 verifier requires all of those,
   `chio.fincred.verifier-policy.v1`, and `evaluate_financial_credentials`; reuse
   present, filter, and challenge, and expose a CLI surface. The old self-rooted
   trust-pack verifier and all production v1 cross-issuer evaluation are
   non-activating compatibility surfaces.
3. Underwriting integration. Add `UnderwritingImportedFinancialEvidence` to
   `chio-underwriting`, populate it in the control plane from typed verified
   credentials, emit
   the `ImportedTrustDependency` signal, and add the golden tests.
4. Cross-issuer aggregation and the external-evidence gate. Wire the v2
   portfolio plus the already-defined trust-pack verifier into storage,
   control-plane, and presentation adapters. Configure the authoritative online
   lifecycle resolver, persist per-passport store-generation/status-version
   high-water marks, and require local trust resolution for every issuer,
   verifier, and migration signature. Land all substitution, stale-Active,
   resolver-outage, key-interval, and rollback negatives, preserve per-issuer
   no-merge evaluation, and document the partner-pilot gate. No cross-org trust
   claim ships.

## Resolved decisions

1. Financial verification uses sibling
   `chio.fincred.verifier-policy.v1`, keeping the trust-only passport policy
   free of economy types. A verifier must satisfy both applicable policies.
2. `PremiumHistoryCredential` may be `verified` at its home issuer only when
   its source floor supports that class. Cross-organization presentation remains
   capped at `asserted`.
3. Issuing a financial credential reuses the operator-authenticated passport
   issuance authority and does not add a v1 ladder class because issuance itself
   moves no value or mutates another party's state. Publishing the containing
   passport uses existing `registry.passport_listing`; revocation uses
   `credentials.passport_revoke`. Any future auto-action based on the credential
   still needs its own pre-action ladder authority.
