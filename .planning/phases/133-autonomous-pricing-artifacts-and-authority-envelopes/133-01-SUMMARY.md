# Summary 133-01

Defined the autonomous pricing-input artifact and the bounded pricing-decision
contract.

## Delivered

- added autonomous pricing input, model provenance, explanation, and pricing
  decision types plus validation in `crates/arc-core/src/autonomy.rs`
- exported the autonomy surface from `crates/arc-core/src/lib.rs`
- published `docs/standards/ARC_AUTONOMOUS_PRICING_DECISION_EXAMPLE.json`

## Result

ARC can now express one reviewable autonomous pricing decision over explicit
underwriting, scorecard, loss, capital-book, and optional web3 evidence.
