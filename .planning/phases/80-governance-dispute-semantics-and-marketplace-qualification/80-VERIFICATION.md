# Phase 80 Verification

status: passed

## Result

Phase 80 is complete. ARC's public certification marketplace now has explicit
governance and dispute semantics, end-to-end qualification, and milestone
closeout evidence strong enough to treat `v2.17` as locally closed.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-cli --test certify certify_check_emits_signed_pass_artifact_and_report -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_marketplace_search_transparency_consume_and_dispute_work -- --exact --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 80`
- `git diff --check`

## Notes

- `v2.17` is closed locally; `v2.18` remains planned-only until phase detail is
  activated
