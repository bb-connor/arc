# Summary 107-03

Defined ARC's local policy import guardrails for public discovery artifacts in
`crates/arc-credentials/src/discovery.rs`, `spec/PROTOCOL.md`, and the
release-facing docs.

Implemented:

- explicit `informational_only`, `requires_explicit_policy_import`, and
  `requires_manual_review` guardrails on every discovery document
- public discovery endpoints that stay unavailable without authority signing
  material
- documentation that visibility, fetchability, and transparency do not equal
  admission
- release and qualification updates that keep the boundary conservative and
  honest

This preserves explicit local activation even after ARC publishes public
discovery artifacts.
