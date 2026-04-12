# Summary 129-02

Froze settlement evidence, dispute, and failure-recovery semantics.

## Delivered

- modeled settlement paths, dispute windows, finality rules, and lifecycle
  states in `crates/arc-core/src/web3.rs`
- made validation fail closed for missing dispute windows, invalid finality,
  or malformed settlement evidence
- recorded the first official dispute and recovery posture in
  `docs/standards/ARC_WEB3_PROFILE.md` and `spec/PROTOCOL.md`

## Result

Settlement evidence, dispute, and recovery semantics are explicit before later
contract and execution work consumes them.
