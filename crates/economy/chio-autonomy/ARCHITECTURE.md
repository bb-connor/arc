# chio-autonomy architecture

## Responsibility and boundary

The public surface contains ten artifact/report families and their
`validate_*` functions, supporting enums and structs, schema constants,
`AutonomyContractError`, and signed-envelope aliases for nine families.
`AutonomousQualificationMatrix` is an unsigned model with a validator.
The crate re-exports `capability`, `receipt`, and `market` for field types, and
`web3` when the `web3` feature is enabled.

The library owns artifact shape and local consistency rules. Applications own
pricing models, evidence resolution, signature verification, live authority
accounting, capital mutation, settlement dispatch, and rollback execution.
An execution record describes supplied state; validation does not observe the
external action. The crate contains no storage or transport implementation.

## Structure

- `model.rs` defines pricing input, authority envelope, decision, capital
  optimization/simulation, execution, rollback, comparison, drift, and
  qualification types. Serde models reject unknown fields and encode enums
  using snake case.
- `validation.rs` implements the ten public validators and shared checks for
  money, identifiers, unique lists, model provenance, and rollback references.
- `error.rs` provides typed errors for schema, missing/duplicate fields,
  reference requirements, and envelope/decision/optimization/execution/drift
  or qualification inconsistencies.
- `lib.rs` selects exports; `src/tests.rs` contains fixtures and regressions,
  and `tests/integration_smoke.rs` checks public construction and defaults.

## Data and control flow

Pricing input records subject/provider/currency, requested coverage, reputation,
loss/capital units, runtime assurance, and evidence references. Its validator
requires underwriting decision, exposure ledger, credit scorecard, and capital
book evidence kinds. Loss units require loss-lifecycle evidence; a populated
settlement state requires web3 settlement evidence. These checks inspect kind
and id presence, leaving retrieval and authentication to the caller.

The authority envelope declares automation mode, permitted actions, money
ceilings, rate/count limits, validity interval, and review thresholds. Decision
validation first checks nested input/envelope and model provenance, then matches
subject/provider/currency, bounds suggested money, and checks explanation and
review state. Only bind dispositions explicitly check the `Bind` permission.
Shadow mode requires `ShadowOnly`; auto-approved decisions cannot exceed a
configured premium-review threshold.

Optimization validation checks facility references, reserve/utilization bounds,
positive capacity, and same-currency recommendations. Capacity shifts require a
destination reference. Simulation validates both embedded optimizations and
requires matching subject/currency, distinct ids, comparison support, deltas,
and an operator action. Delta values are supplied observations; no optimization
engine computes or verifies their economic effect here.

Execution validation checks reference presence, unique safety gate names,
rollback/contact references, and action-specific quote/bind/settlement fields.
`Executed` requires all gates passed; `Blocked` requires a failed gate.
Executed binds require a settlement dispatch reference. Drift validation checks
nested rollback/comparison artifacts and requires every critical signal kind
to appear in rollback triggers with `fail_safe_engaged` set.

## Trust and invariants

Each public validator checks its exact schema string. Monetary values checked
by these validators must be positive and use a three-letter uppercase currency;
comparisons use exact currency strings. Basis-point fields have the bounds
specified by their owning validator. Required string helpers reject blank
values; unique string lists also reject padding and duplicates.

`SignedAutonomous*` and `SignedCapitalPool*` are aliases for
`SignedExportEnvelope<T>`. The validators consume artifact bodies and do not
verify envelope signatures, perform canonical ingress decoding, or authenticate
referenced ids. Callers must apply the protocol's canonical signing and trusted
key verification at their own ingress boundary.

An authority interval is checked for ordering, but decision validation does not
compare it against current time. Daily decision and rate-change limits are
modeled fields; the validator checks their configured ranges without enforcing
runtime usage counters or historical rate differences. Support flags describe
supplied scope; only the specific flags consulted by a validator constrain it.

Rollback validation requires nonempty, unique triggers/actions and identifiers.
It does not enforce `requires_operator_ack` or execute the selected safe state.
Drift validation trusts the supplied severity and engaged flag; it does not
compare observed metrics with thresholds to infer severity. Qualification
validation checks case shape and uniqueness without requiring expected and
observed outcomes to agree. Preserve these distinctions in operator reports.

## Dependencies

`chio-core-types` supplies `MonetaryAmount`, runtime assurance tiers, and
`SignedExportEnvelope`. `chio-market` supplies `LiabilityCoverageClass`;
`chio-web3`, optional behind the `web3` feature, supplies
`Web3SettlementLifecycleState`. Serde implements artifact
serialization and deserialization; `thiserror` formats the closed error enum.
`serde_json` supports reference-fixture parsing in tests. The `web3` feature
(off by default) enables `chio-web3`, the `web3` re-export, the
`latest_web3_settlement_state` pricing-input field and its evidence check;
without it, a pricing input carrying that field fails deserialization.
The manifest declares no benchmark targets.

## Verification

Run `cargo test -p chio-autonomy` for the unit and integration tests.
`reference_artifacts_parse_and_validate` loads the reference authority,
decision, optimization, simulation, execution, comparison, drift, and
qualification JSON documents from `docs/standards` and applies the validators.
Regressions reject missing required evidence, padded money currency, duplicate
explanations/triggers, invalid shadow and human-review states, mismatched
simulation subjects, missing executed-bind dispatch, and unengaged critical drift.

The public smoke tests construct evidence references and check the pricing
support defaults: delegated authority, live bind, reserve optimization, and
operator override are all enabled. Capital optimization defaults keep live
mutation and cross-currency optimization disabled. These defaults are artifact
metadata; runtime enforcement is owned by the integrating application.

See the [README](README.md),
[autonomous pricing profile](../../../docs/standards/CHIO_AUTONOMOUS_PRICING_PROFILE.md),
and [protocol serialization contract](../../../spec/PROTOCOL.md#41-canonical-json).
