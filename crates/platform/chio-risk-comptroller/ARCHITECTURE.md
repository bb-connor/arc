# chio-risk-comptroller architecture

## Responsibility and boundary

`RiskComptrollerReport` represents a risk authority report for a transaction
passport/order/subject. It contains facility state and transitions,
coverage, reconciliation, premiums, actuarial evidence, insurance copy,
capital decomposition/instructions, reserve and sanction ledgers, appeals,
and asserted verified claims. Most fields are private; ID, order, subject,
signature, and the claim accessor are public.

The library supplies report consistency, signature, portfolio, and reference
checks. Callers authenticate passport roots, choose risk-authority keys, and
resolve external evidence. No pricing engine, fund custody, payout executor,
or sanction enforcement exists here.

## Structure

`lib.rs` defines report types and validates facility replay, coverage
identity, reconciliation, premium/payment references, actuarial backtests,
capital adequacy, instruction bindings, coverage claim scope, and
appeal/closure conditions. `ledger.rs` validates reserve and
sanction-reserve transitions. `evidence_refs.rs` checks referenced artifacts
through infallible or fallible callbacks. `validation_helpers.rs` is
included for shared validation utilities.

## Data and control flow

`validate_signed_risk_report` authenticates a `serde_json::Value`, projects
it to the strict report type, and invokes structural/business consistency
checks against the passport. The signature encoding carries an Ed25519 key
and signature under `sig-ed25519:`. Verification removes only the signature
field and checks the remaining canonical value against the caller pin set.

`validate_risk_report` can also validate an already typed report directly.
`validate_risk_portfolio_reports` aggregates reports sharing
facility/currency and checks allocation and consumption. Reference
validation is a separate operation because the graph and artifacts belong to
the composing verifier.

## Trust and invariants

Signature-only validation does not decode the report schema or check report
arithmetic. Typed report validation does not verify a signature. The
combined helper performs both but cannot recover original duplicate JSON
fields once input has become a `Value`; callers use a strict original-byte
decoder first.

Reserve replay rejects duplicate entry IDs/receipt refs and repeated
terminal consumption of one reserve/claim. Reverse slashes require prior
slashes and cannot exceed them. Checked arithmetic preserves accounting
failures. Empty reserve ledgers are accepted when consumed reserve and
payout totals are zero. Fallible evidence callbacks propagate
decode/authentication errors; callbacks that merely report existence
establish only existence.

## Dependencies

`chio-core-types` supplies Ed25519 key parsing and canonical verification.
`chio-transaction-passport` supplies passport bindings and shared domain
errors. `chrono` parses report/backtest timestamps. `serde`/`serde_json`
define strict report projection. Integration tests use `jsonschema` to
compare accepted report shapes with the published schema. No Cargo features
are declared.

## Verification

`tests/risk_comptroller.rs` validates the autonomous-commerce fixture and
mutates lifecycle, premium, capital, backtest, ledger, appeal, and
counterparty bindings. It checks untrusted signatures, portfolio excess,
double consumption, and evidence references. Run `cargo test -p
chio-risk-comptroller --test risk_comptroller`; the library unit-test target
is disabled. The README uses tracked fixtures and an independently written
public-key pin; it validates report consistency without executing money
movement.
