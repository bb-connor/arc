# Process SDK corpus reconciliation plan

> **For agentic workers:** Use superpowers:executing-plans in Root's native
> thread. Claude reviews the complete composition. Root remains the sole
> integration writer and publisher.

**Goal:** Recover the preserved F086 and worker-protocol repairs on the merged
foundation, with shared Rust, Python and TypeScript conformance evidence.

**Architecture:** Reuse the existing `chio.process.v1` corpus and schemas.
Expose the worker's existing recovery and preparation operations in the Node
client. Preserve fail-closed response decoding and the declared intent schema.
Do not introduce a new transport, protocol, parser framework or authority path.

**Base:** `28d826e3e6b73af22388fc4eb117b3d8184ba5cf`.
**Sources:** F086 in `docs/reviews/2026-10-06-pr1160/findings.md` and the
preserved `hammer/arch-contracts` producers listed below.

## Constraints and review focus

This is a private follow-up. Keep #1201 and #1202 unchanged and keep the active
landing queue at two PRs. Publication follows their sequential landings and
requires reconciliation against the actual new base.

Unknown fields must not disappear from a governed intent before hashing.
Valid intent serialization and caller-defined context must remain unchanged.
Clients must emit identical recovery frames and reject malformed response
encodings without reconnecting or falling back to a weaker recovery mode.
Packing a package must not silently lose the shared corpus qualification.
Retain failed, passing and unavailable checks separately.

## Task 1: Restore the existing protocol contract

Files: `spec/PROTOCOL.md`, `spec/fixtures/chio-process-v1.json`,
`spec/schemas/chio-process/v1/{request,response}.schema.json`, schema coverage
and manifest, and `crates/kernel/chio-process/WORKER_PROTOCOL.md`.

- [x] Compose `78326bfd3c`, preserving current unrelated schema entries.
- [x] Regenerate the manifest from the actual schema inventory and run
  `bash scripts/check-chio-schema-registry.sh`. Expect no missing or stale
  schema, registry or manifest entries.

## Task 2: Reconcile SDK repairs with genuine failure evidence

Files: `sdks/typescript/packages/process/{index.mjs,index.d.ts,README.md,test}`
and `sdks/python/chio-process/{src/chio_process/__init__.py,tests}`.

- [x] Retain current-source F086 failure: two new assertions fail without the
  repair; the preserved repaired package passes all nine tests, including
  from an offline installed tarball.
- [x] Retain shared-corpus Original failures: Node accepts a BOM; Python accepts
  nonfinite constants, a BOM and encoded surrogates, and leaks RecursionError.
- [x] Compose `e3a84d7978`, `4b5d52273d` and `267a80f7d0`.
- [x] Run all Node process tests and Python process tests with the shared corpus
  present. Expect zero failed or missing corpus cases; schema tests must run.

## Task 3: Bind the Rust worker to the same contract

Files: `crates/kernel/chio-process/tests/protocol_fixtures.rs`,
`crates/core/chio-core-types/src/capability/{governance.rs,tests/governed_intents.rs}`
and the existing corpus's unknown-intent-member case.

- [x] Apply the regression oracle from `068e27de26` without its production fix.
  Run the focused core-types test. Expect deserialization to accept the unknown
  member, causing the intended refusal assertion to fail.
- [x] Compose the production repair and corpus delta from `068e27de26`, then
  the real worker socket corpus consumer from `9faa43e5c0`.
- [x] Run owning core-types and process tests, including the socket corpus,
  and strict owning Clippy. Expect no failure or warning.

## Task 4: Qualify and preserve the bounded wave

- [x] Check formatting and schema compatibility, inspect exact source deltas,
  and record producer-to-integration identities and evidence hashes.
- [x] Obtain Claude's independent whole-composition review, address concrete
  findings, and record remaining native/hosted acceptance separately.
- [x] Update the coordination board with the private candidate. Do not open a
  third PR or publish this branch before the current two-PR queue advances.

## Rulings

- Reuse the complete existing corpus, including the unknown-member refusal,
  instead of deleting that case to keep the wave SDK-only. This requires the
  preserved, narrowly scoped production core-types repair and owning Rust
  evidence. If incompatible callers rely on undeclared fields, they will now
  receive the refusal already required by the schema.
- The corpus exists on `hammer/arch-contracts` and already contains true,
  false, invalid recovery-flag and preparation cases. A fresh fixture would
  duplicate that work. No new corpus format is needed.

## Qualification repair

The composition review found that source CI could skip all five schema tests.
Root also reproduced missing shared-corpus skips after the qualifier copied
consumer tests outside the checkout. Both are fixed in this wave: absent corpus
is an error, the installed qualifier binds the canonical corpus and its hashes,
and source CI installs pinned validators and requires schema validation.
Five focused regressions exercise the actual copied consumers. Offline wheel,
rebuilt-sdist wheel and Node tarball tests execute the behavioral corpus.
The wheel environments retain five optional schema-tool skips; all five schema
tests separately pass in mandatory source mode.

See [the qualification record](../../security/audits/process-sdk-corpus-20261012.json)
for producer mappings, original failures, retained invalid attempts, component
evidence, review findings and remaining native/hosted acceptance.
