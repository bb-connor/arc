# Guard and security reader boundaries

Base: `90e8f0683b251b49cccbaa6d94d554c53eb88932`, branch `packet/3-retention-accounting`, isolated checkout `/tmp/arc-security-launch`.
Scope: all 33 paths pinned in the trust reader batch's `next-readers.json`, plus shared helpers and direct consumers required to enforce their actual contracts.
Authority: mechanisms B/C in `2026-09-26-unrepresentable-defects-design.md`, `docs/security/signed-json-boundaries.md`, and remaining-security-work item 2.

## Tasks

1. Guard decisions and loading: validate bounded original external verdicts and native arguments; preserve error causes without exposing response bodies; harden registry/cache/marketplace, classification/embedding and WASM input custody.
2. Security execution and recovery: preserve sandbox canonical/authenticated bootstrap, quarantine state/effect-journal identity and replay checks, keyring signature/checkpoint contracts and decoy integrity gates; repair unsafe readers and record already constrained ones honestly.
3. Security-type deserializers: validate existing constructor, collection and identifier invariants, repair concrete bypasses and add production-linked negative controls.
4. One final independent source review, focused package/features qualification, semantic inventory, exact source/evidence hashes, roadmap update and local conventional commit.

## Decisions and verification

- Preserve native signed full-width integers. External I-JSON uses original validation before projection. Exact canonical owners retain byte equality before effects or trust.
- Input parsing never substitutes for authentication, signature, replay, policy or authority checks.
- Follow the user's action-first directive: implement in batches, then run focused checks; no repeated baseline/full-workspace builds or per-edit test campaign.
- Inspect already constrained custom deserializers and canonical readers without redundant rewrites. Classification is review debt, not a vulnerability count.
- One fresh read-only review, no delegated implementation. Keep unrelated `output/` untouched.
- Local qualification does not establish hosted, native enforcement, device, M5 or release acceptance. No push, merge, publication or activation.

## Completion

All four tasks are complete in the local scope. The
[execution record](../../reviews/2026-09-30-guard-security-readers-execution.md)
and [terminal evidence](../../reviews/artifacts/2026-09-30-guard-security-readers/README.md)
record the implemented repairs, retained existing contracts, review resolutions,
failed attempts, focused reruns, consumer compilation and remaining acceptance
boundaries. The next implementation batch is the 31 pinned platform readers.
