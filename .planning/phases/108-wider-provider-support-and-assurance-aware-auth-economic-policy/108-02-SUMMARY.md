# Summary 108-02

Threaded runtime-assurance provenance into ARC's standards-facing auth and
economic policy surfaces in `crates/arc-kernel/src/operator_report.rs`,
`crates/arc-store-sqlite/src/receipt_store.rs`, `crates/arc-core/src/credit.rs`,
`crates/arc-core/src/underwriting.rs`, and
`crates/arc-cli/src/trust_control.rs`.

Implemented:

- `runtimeAssuranceSchema` and `runtimeAssuranceVerifierFamily` on enterprise
  authorization-context transaction projection
- fail-closed authorization export when runtime-assurance projection is
  incomplete
- provider-risk and facility-policy runtime-assurance state that now preserves
  schema, family, verifier, evidence digest, and observed verifier families
- one explicit local narrowing rule: heterogeneous verifier-family provenance
  requires manual review before ARC auto-allocates facility capital

This keeps portable assurance policy-visible and auditable without allowing it
to silently widen rights or economic ceilings.
