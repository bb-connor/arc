# Economy authority reader implementation plan

> Use `superpowers:executing-plans` inline. The user explicitly authorized this
> complete batch and continues the commit/push cadence. One final independent
> review covers the complete batch; no delegated implementation.

**Goal:** Dispose all 22 economy reader paths pinned by the platform handoff,
repair their concrete input, rejection, authority and lifecycle defects, and
publish locally qualified source with the next exact remaining queue.

**Architecture:** Consume the existing `UntrustedJsonText` original-byte owner.
Each crate keeps its own input/error owner. Native signed full-width integers,
strict external I-JSON and unsigned document semantics remain distinct.
Authentication, pinning, exact digest, tenant and replay checks remain required.

**Tech stack:** Rust workspace, Serde, existing canonical JSON/clock types,
Reqwest, existing evidence/settlement fixtures and source ratchets.

**Spec:** `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md`,
mechanisms A/B/C; `docs/security/signed-json-boundaries.md`;
`docs/reviews/2026-09-28-remaining-security-work.md`, item 2.

**Base:** `593b642da96bba939e4ae26055f2ebe26b06668c`, existing isolated worktree
`/tmp/arc-security-launch`, branch `packet/3-retention-accounting`.

## Constraints and review focus

- Preserve existing canonical byte equality and owner-specific size limits.
- New native credit/factor input bound: 4 MiB. Financial-source artifacts retain
  512 KiB and their existing collection limits. Input causes have safe display.
- Keep byte bounds before projection and transport retention before parsing.
- Preserve full-width monetary integers; do not narrow native writers into I-JSON.
- No legacy decoder fallback, raised source caps or new lint exceptions.
- Review malformed ignored nested fields; valid numeric encodings; transport
  overrun; request/result substitution; future/regressing authority time.
- Local tests and source gates do not imply live providers, native execution,
  hosted qualification, supply-chain audit, M5 or release acceptance.

### Task 1: Credit and fiscal evidence (8 readers)

**Files:** Five pinned credit paths and three fiscal paths, crate-local input
helpers, their public error enums and existing integration/unit tests.
**Interfaces:** `input::canonical<T>(bytes, bound)` returns
`Result<T, SharedUntrustedJsonError>`; owner errors retain that source.

- [x] Add original malformed-input source/redaction and over-bound regressions
  at public canonical readers; retain valid signed full-width integer controls.
- [x] Run those controls before implementation and retain terminal results.
- [x] Migrate original native parsing and exact canonical equality; retain body,
  lineage, signer and explicit-now validation in their existing owners.
- [x] Run complete credit/fiscal package tests and record actual results.

### Task 2: Settlement and replay (6 readers)

**Files:** Pinned CCIP, replay, config, observation, publication and retry paths;
settlement/channel/publisher errors and focused tests.
**Interfaces:** bounded original native replay; strict external canonical
response decoding; fixed wire outcome/error classification with local causes.

- [x] Reproduce cause loss, alternate-transport response overflow and malformed
  dead-letter acceptance using real decoder/publisher paths.
- [x] Preserve replay signer/digest and observation/publish request bindings;
  bound config reads and alternate transport output before projection.
- [x] Remove legacy dead-letter decoding and require a nonzero attempt count.
  Classify the CCIP embedded fixture separately from production ingress.
- [ ] Finish source-preserving consumer compilation; settlement package tests passed.

### Task 3: Markets, predicates and external witnesses (8 readers)

**Files:** Pinned open-market, market, listing, Chainlink and Rekor/witness
paths; local input/clock/error owners and production-linked tests.
**Interfaces:** Original native purchase members and exact external recovery
members retain their separate contracts. Predicate evaluation exposes a local
input cause with the existing closed wire verdict. Rekor retains pinned SET and
Merkle authentication, bounded transport/nested input and a fenced clock.

- [x] Add duplicate, source/redaction, oversized original input and correct
  numeric-profile controls; exercise public/effect-facing paths where available.
- [x] Implement bounded native/external readers, predicate cause custody,
  bounded Rekor response/proof retention and shared fallible authority time.
- [x] Verify exact publish/receipt identity and request binding; fail closed on
  future/regressing witness time without manufacturing an epoch timestamp.
- [ ] Finish direct consumer compilation; all affected owning packages passed.

### Task 4: Review, accounting, qualification and publication

- [ ] Obtain one fresh independent review; fix material findings and qualify them.
- [ ] Record every pinned reader and supporting owner, preserve terminal failed
  attempts, refresh the inventory and pin the next substantial batch.
- [ ] Run scoped all-target Clippy, format, trust/clock/negative/hygiene/wire gates.
- [ ] Commit and non-force push the complete source/evidence; verify remote SHA.

## Execution record

The per-task ledger and terminal evidence live in
`docs/reviews/artifacts/2026-10-01-economy-authority-readers/`.
