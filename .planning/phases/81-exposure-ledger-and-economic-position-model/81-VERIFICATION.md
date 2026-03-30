# Phase 81 Verification

status: passed

## Result

Phase 81 is complete. ARC now has a canonical signed exposure-ledger export
that projects governed economic position from receipt, settlement,
metered-billing, and persisted underwriting-decision truth without cross-netting
currencies or fabricating ambiguous rows.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-core --lib credit -- --nocapture`
- `cargo test -p arc-cli --test receipt_query exposure_ledger -- --nocapture`
- `git diff --check`

## Notes

- the exposure ledger is the signed economic-position substrate for later
  scorecard, facility, and capital-policy phases
- claim adjudication and recovery lifecycle semantics remain intentionally
  narrower than a full liability or claims network in this phase
