# chio-risk-comptroller

Checks risk-comptroller report signatures, facility lifecycle, coverage,
premium, actuarial limits, capital, reserve ledgers, and appeals. Other Chio
proof verifiers compose these checks with their evidence graphs.

## Usage

Validate the tracked report with an explicit fixture-authority pin. Both
documents are embedded at compile time. This helper authenticates the report
and checks its consistency against the supplied passport ID; callers
separately authenticate that passport.

```rust
use chio_core_types::PublicKey;
use chio_risk_comptroller::validate_signed_risk_report;
use chio_transaction_passport::{decode_evidence_json, TransactionPassport};

let passport: TransactionPassport = decode_evidence_json(include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/proof-room/",
        "enterprise-export/valid-autonomous-commerce/transaction-passport.json")))?;
let value: serde_json::Value = decode_evidence_json(include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/proof-room/",
        "enterprise-export/valid-autonomous-commerce/risk-comptroller-report.json")))?;
let trusted = PublicKey::from_hex(
    "3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2")?;
let report = validate_signed_risk_report(&passport, &value, &[trusted])?;
assert_eq!(report.id, "risk-comptroller-enterprise-valid");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`validate_signed_risk_report` calls `validate_risk_report_signature`,
decodes the typed report, then calls `validate_risk_report`. Signature-only
validation removes `signature` and checks canonical bytes against
caller-trusted Ed25519 keys.

`validate_risk_portfolio_reports` checks shared-facility accounting across
supplied reports. `try_validate_risk_evidence_refs` propagates failures from
the caller’s reference lookup; `validate_risk_evidence_refs` accepts an
infallible membership callback. Each reference check depends on that
callback’s authentication and evidence-role checks.

## Status

Implemented offline report validators. `[lib] test = false`; integration
tests provide coverage. Internal consistency checks execute no capital
instructions, payouts, or sanctions. The signature helper receives a
`serde_json::Value`, so callers must validate original bytes before
duplicate or numeric provenance is lost.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#643-transaction-passport-proof-root)
- [chio-enterprise-export](../chio-enterprise-export/README.md)
- [License](../../../LICENSE)
