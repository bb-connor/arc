# chio-market architecture

## Responsibility and boundary

The crate owns liability-market artifacts and validation: providers,
delegated pricing authority, quotes, placements, bound coverage, claims,
disputes, adjudications, payout instructions, and settlement reconciliation.
It also exposes `quote_and_bind`, `BoundPolicy::file_claim`, and verified
parametric policy, evidence, trigger, and lifecycle types.

Host services own provider discovery, authority configuration, durable state,
receipt resolution, and value-moving execution. `ClaimSettlementSink` is the
dispatch seam. A successful sink call supplies a settlement reference; the
library has no rail client or settlement store.

## Structure

`provider.rs` defines jurisdiction, coverage-class, evidence, provenance,
lifecycle, and support-boundary records. `quote.rs` contains requests,
responses, quote terms, and pricing authority. `placement.rs` models placement,
bound coverage, and auto-bind decisions. `workflow.rs` projects market rows.

`claim.rs` defines packages, provider responses, disputes, and adjudications.
`settlement.rs` defines payout and settlement instructions, receipts, role
topologies, reconciliation states, and workflow queries. `error.rs` separates
market validation failures from caller-seam failures.

`insurance_flow.rs` implements premium binding and receipt-backed claims.
`parametric.rs` defines policies, predicates, schedules, identities, and
verification contexts. Its `evidence`, `claim`, and `lifecycle` submodules
handle authenticated corpora, contest/payout contracts, and economic-state
projections.

## Data and control flow

1. A host validates a provider record and selects jurisdiction, currency,
   coverage, and authority appropriate to its request.
2. Signed quote, placement, coverage, and claim artifacts preserve the
   references required by later payout and reconciliation artifacts.
3. `quote_and_bind` obtains `PremiumInputs` from the injected source and
   calls governed fiscal premium pricing. A quoted result becomes an active
   `BoundPolicy`; default coverage is 100 times the premium, saturating at
   the monetary integer limit.
4. `file_claim` validates the supplied claim and current policy, resolves
   every supporting receipt, and verifies its returned signature.
5. An approved amount is capped by coverage and sent to the settlement sink.
   Resolver failures produce classified denial reasons; sink failures return
   seam errors for the host to handle.

The parametric path verifies a signed policy against coverage and configured
parties, verifies a complete evidence corpus under a trusted source registry,
then evaluates a guard-denial, drift-severity, or settlement-failure predicate.
Its claim identity commits policy and coverage body digests, subject,
predicate, window, and evidence range. A verified fired trigger can open a
claim and feed `prepare_parametric_claim_opening` for economic-state updates.

## Trust and invariants

Artifact `validate` methods enforce their own amount, currency, state, and
nested-reference conditions. Schema and authority enforcement varies by
entry point; hosts must validate original wire inputs and select trusted
signers. Shared envelope validation checks embedded signatures. The consuming
service must prove referenced state is current and authorized for its action.

`LiabilityProviderSupportBoundary` defaults to curated registration with
automatic trust admission, permissionless federation, and bound coverage
disabled. `LiabilityProviderReport::validate` requires jurisdiction policies,
coverage classes, currencies, positive quote TTLs, and unique normalized
jurisdictions. Those fields express policy rather than proving insurer status.

`file_claim` compares the resolver's declared digest to each fingerprint and
verifies returned bytes with the resolver's returned signer key. It does not
independently pin that key or recompute the digest from those bytes. The
evidence source owns those checks and the receipt's relevance to the incident.
This flow has no retained claim replay ledger; sinks must coordinate duplicate
requests and durable settlement independently.

`VerifiedParametricPolicy` checks configured policy and coverage signers and
binds parties, funding, payout rail, and evaluator context. Its canonical
loader caps the original input. Evidence verification uses source checkpoints
and authenticated ranges. Payout arithmetic rejects currency/unit mismatch,
overflow, and coverage excess.

Parametric claim state includes versions and lifecycle fences. Opening
projections use a verified economic-state view and transition-proof verifier.
Preparing a batch does not durably commit it. The shared economic coordinator
and host store own atomic retention and effect reservation.

## Dependencies

`chio-underwriting` prices premiums; `chio-fiscal` authorizes governed pricing.
`chio-credit` supplies capital and execution contracts. `chio-appraisal`
supplies risk-package types. `chio-core-types` supplies keys, envelopes,
canonical JSON, receipts, Merkle proofs, and economic-continuity primitives.
`serde`, `serde_json`, and `thiserror` support wire forms and errors.

## Verification

`src/tests.rs` covers provider, quote, placement, claims, settlement, and
parametric contracts. `tests/insurance_flow.rs` uses fiscal fixtures, in-memory
receipt sources, and capturing settlement sinks to test binding and claims.
Parametric input tests exercise duplicate/canonical-input rejection, while
replay tests cover retained opening projections and semantic or batch drift.

Run `cargo test -p chio-market`. The local fixture and seam tests exercise
library decisions; they do not establish a live insurer relationship,
durable duplicate-effect handling, or external payout finality.
