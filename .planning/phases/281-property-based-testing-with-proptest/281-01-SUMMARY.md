# Summary 281-01

Phase `281-01` established crate-owned property testing for the core
correctness invariants the milestone called out:

- [property_invariants.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-core/tests/property_invariants.rs) now uses `proptest` to prove Ed25519 capability-token signing roundtrips over arbitrary payloads, rejects body mutation after signing, preserves attenuation subset relationships, and rejects child scopes that add operations the parent never granted
- [property_budget_store.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/tests/property_budget_store.rs) now drives random budget-operation sequences against `InMemoryBudgetStore` and a simple model so budget accounting stays fail-closed under arbitrary credits, spends, refunds, and overflow attempts
- Workspace and crate manifests now include `proptest` as an explicit dev dependency so the property suites run as a first-class part of the repo rather than one-off local experiments

Verification:

- `cargo test -p arc-core --test property_invariants -- --nocapture`
- `cargo test -p arc-kernel --test property_budget_store -- --nocapture`
- `cargo fmt --all -- --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/281-property-based-testing-with-proptest/281-01-PLAN.md`
