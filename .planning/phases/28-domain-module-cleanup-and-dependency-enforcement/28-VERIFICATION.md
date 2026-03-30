status: passed

# Phase 28 Verification

## Result

Phase 28 passed. The remaining domain monolith files are now thin facades over
named modules, and the workspace has an executable layering guardrail that
blocks CLI and HTTP dependencies from leaking back into the core domain crates.

## Evidence

- `cargo check -p arc-credentials -p arc-reputation -p arc-policy`
- `wc -l crates/arc-credentials/src/lib.rs crates/arc-reputation/src/lib.rs crates/arc-policy/src/evaluate.rs`
- `./scripts/check-workspace-layering.sh`
- `cargo test -p arc-credentials -- --nocapture`
- `cargo test -p arc-reputation -- --nocapture`
- `cargo test -p arc-policy -- --nocapture`
- `rg -n "check-workspace-layering|WORKSPACE_STRUCTURE" scripts/ci-workspace.sh docs/architecture/WORKSPACE_STRUCTURE.md`

## Notes

- facade line counts dropped to 39 lines for `arc-credentials/src/lib.rs`,
  24 lines for `arc-reputation/src/lib.rs`, and 22 lines for
  `arc-policy/src/evaluate.rs`
- the new layering check is enforced through `scripts/ci-workspace.sh`, so the
  broader qualification lane now inherits the architecture guard automatically
