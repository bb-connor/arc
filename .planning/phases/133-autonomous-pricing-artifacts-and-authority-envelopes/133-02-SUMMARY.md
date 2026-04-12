# Summary 133-02

Defined the autonomous pricing authority-envelope contract and its fail-closed
approval constraints.

## Delivered

- added authority-envelope kinds, automation modes, permitted-action limits,
  premium review thresholds, and envelope validation in
  `crates/arc-core/src/autonomy.rs`
- published `docs/standards/ARC_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE.json`

## Result

Pricing automation is now subordinate to one explicit signed envelope instead
of inheriting ambient insurer-like authority.
