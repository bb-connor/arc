# chio-underwriting architecture

## Responsibility and boundary

The public surface owns underwriting query/evidence shapes, deterministic
decision evaluation, decision-artifact IDs, premium calculation, tier limits,
and simulation/appeal records. It performs no evidence collection or durable
lifecycle operations. Callers establish snapshot authenticity and completeness.

`SignedUnderwritingPolicyInput` and `SignedUnderwritingDecision` are aliases
of the shared signed export envelope. Evaluation takes a plain policy-input
value; its entry point does not verify an enclosing signature. Application
boundaries handle issuance, persistence, supersession, appeal authorization,
and eventual enforcement of recommendations.

## Structure

| Module | Responsibility |
| --- | --- |
| `lib` | Risk taxonomy, scoped queries, evidence snapshots, appeals, schema constants. |
| `decision` | Policy validation, findings, outcomes, decision IDs, budget and premium recommendations. |
| `premium` | Compliance/behavioral score pricing and fiscal insurance schedules. |
| `marketplace_limits` | Reputation-tier ceilings and supplied revocation decisions. |

All three functional modules are public and selected types/functions are
re-exported at the crate root. `appraisal` and shared core type modules are
also re-exported for downstream artifact construction.

## Data and control flow

`UnderwritingPolicyInputQuery::validate` requires a capability, agent, or tool
server anchor, rejects padded/empty filters, requires a server for tool names,
and rejects inverted time ranges. Receipt limits normalize into 1..=200.
Callers invoke query validation before collecting a snapshot.

`evaluate_underwriting_policy_input` validates the decision policy, then folds
receipt history, freshness, compliance availability, reputation, runtime
assurance, and risk signals into findings. After deduplication, the maximum
outcome selects `Approve`, `ReduceCeiling`, `StepUp`, or `Deny`; risk class is
folded similarly. A reduced ceiling uses the configured factor. The evaluator
itself does not validate the snapshot query or authenticate evidence references.

`build_underwriting_decision_artifact` consumes an already computed evaluation,
derives review/budget/premium recommendations, and hashes canonical content
into `decision_id`. It returns an active artifact;
storing or replacing that artifact is the caller's operation. Simulation
records carry both evaluations and deltas over the supplied input.

## Trust and invariants

`PremiumInputs::validate` checks nonzero base rate, currency shape, bounded
compliance score, and finite behavioral inputs. `price_premium` declines missing
compliance scores. Absolute anomaly beyond the threshold incurs a rounded,
capped deduction before the risk band is selected. Default quote bands multiply
the base by 2, 3, or 6; combined scores below 500 decline.

Monetary quoting uses checked `u128` fixed-point arithmetic and half-up rounding.
The unconfigured schedule also declines base rates above 2^53. Governed fiscal schedules
can price larger exact integer amounts within the `u64` result bound, and
replace caller tuning with resolved schedule parameters. Fiscal denial returns
an error rather than a quote.

`compute_marketplace_credit_limit` returns `Deny` for supplied revocation or
a currency other than USD. Its four default ceilings are 10,000, 50,000,
250,000, and 1,000,000 minor units. Tenant ID, reputation tier, and revocation
standing are caller inputs; the helper contacts no revocation service.
Fiscal limits select currency-bound governed ceilings or explicit bootstrap
fallback and retain the revocation check.

## Dependencies

`chio-core-types` supplies monetary amounts, assurance tiers, canonical hashing,
and signed envelopes. `chio-appraisal` supplies verifier families and related
appraisal contracts. `chio-fiscal` resolves decision premiums, insurance
schedules, and tier-limit tables. Serde defines the serializable evidence and
report surface; `thiserror` carries fiscal adapter failures. There is no kernel
or database dependency, and no Cargo features are declared.

## Verification

Use `cargo test -p chio-underwriting`.
Decision unit tests exercise invalid policies, insufficient/stale history,
compliance requirements, signal folding, premium/budget recommendations, and
decision artifact fields and envelope signatures. Premium unit and integration
tests check clean versus
riskier history, decline floors, missing scores, anomalies, precision limits,
and governed schedules. Marketplace tests check each tier, revocation denial,
USD enforcement, and fiscal parity. The integration smoke test checks a
scoped query and default policy. These tests supply evidence snapshots directly.

[README](README.md) · [Appraisal](../chio-appraisal/README.md)
