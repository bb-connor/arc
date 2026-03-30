# Phase 89 Verification

status: passed

## Result

Phase 89 is complete. ARC now has one curated liability-provider registry with
signed provider-policy artifacts, durable supersession-aware publication, and
fail-closed provider resolution over explicit jurisdiction, coverage-class,
currency, and evidence-requirement policy.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-core market -- --nocapture`
- `cargo test -p arc-cli --test receipt_query liability_provider -- --nocapture`
- `git diff --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 90`

## Notes

- provider publication remains curated and operator-controlled rather than a
  permissionless trust source
- resolution fails closed unless one active provider policy matches provider
  id, jurisdiction, coverage class, and currency exactly
- this completes phase `89` and advances the autonomous cursor to phase `90`
