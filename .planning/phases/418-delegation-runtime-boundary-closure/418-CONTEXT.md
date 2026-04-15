# Phase 418 Context: Delegation Runtime Boundary Closure

## Why This Phase Exists

ARC already has delegation helpers, attenuation semantics, and lineage data
structures, but the current runtime boundary is still weaker than the
strongest recursive delegated-authority story. That makes bounded ship honesty
depend on either runtime closure or explicit claim narrowing.

Phase `418` exists to settle that boundary explicitly.

## Required Outcomes

1. Decide whether the bounded ship will add runtime delegation-chain and
   attenuation enforcement or will explicitly narrow the release boundary to
   root-issued or authority-reissued semantics.
2. Make revocation and lineage wording match the runtime path that actually
   ships.
3. Ensure examples and qualification docs do not teach stronger recursive
   delegation semantics than the bounded release supports.

## Existing Assets

- `docs/review/02-delegation-enforcement-remediation.md`
- `crates/arc-core-types/src/capability.rs`
- `crates/arc-kernel/src/kernel/mod.rs`
- `spec/PROTOCOL.md`
- `docs/release/QUALIFICATION.md`

## Gaps To Close

- runtime helpers exist, but hot-path admission still does not enforce the full
  stronger delegation story
- ship-facing language still risks implying recursive lineage completeness
- examples and release docs have not yet been re-baselined on the bounded
  delegation claim

## Requirements Mapped

- `DELEG5-01`
- `DELEG5-02`

## Exit Criteria

This phase is complete only when the bounded ARC release says exactly what the
runtime enforces for delegated authority and nothing stronger.
