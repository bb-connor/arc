# Economy authority reader execution

Base: `593b642da96bba939e4ae26055f2ebe26b06668c`, branch
`packet/3-retention-accounting`, checkout `/tmp/arc-security-launch`.
Scope: all 22 economy paths pinned by the platform handoff, supporting owners
and direct consumers. This continues remaining-work item 2 and approved
unrepresentable-defects mechanisms A/B/C.

## Implemented tasks

1. **Credit and fiscal evidence (8 pinned readers).** Native typed canonical
   imports check original bytes and owner budgets before projection or authority
   verification. Credit/factor readers use a 4 MiB cap; financial source members
   retain 512 KiB and existing collection budgets; fiscal readers retain their
   existing limits. Input causes survive owner errors with safe formatting.
   Body, signer, lineage, exact binding and explicit trusted-time checks remain.
   Native readers retain full-width integer support; each body's existing
   safe-integer constraints remain separate semantic checks.
2. **Settlement, replay and terminal records (6 pinned readers).** Replay pins
   and descriptors keep canonical identity and configured authority checks.
   Deployment file reads bound actual retained bytes. Observation and publisher
   responses preserve strict external canonical bytes, schema and exact request
   digest bindings. Publisher limits now also cover alternate transports.
   Dead-letter decoding accepts only the closed typed reason schema and rejects
   zero attempts; the legacy string-reason fallback is removed. CCIP's sole
   lexical decoder is an embedded repository fixture, not production ingress.
3. **Markets, predicates and witnesses (8 pinned readers).** Purchase member
   digest construction cannot erase duplicate original keys. Recovery keeps its
   stricter external canonical contract and authenticated receipt/purchase
   bindings. Parametric imports retain native canonical bytes and authority
   checks. Predicate parsing is bounded and exposes a local native cause while
   preserving the closed wire verdict and deterministic evaluation identity.
   Rekor bounds HTTP retention and nested base64/JSON, requires a single entry,
   validates SHA-256 hash shape, and binds receipt time to the signed entry.
   Pinned SET signatures and optional Merkle proofs remain required. Publication
   and verification use a shared fallible clock with clone-shared regression
   fences. Chainlink validates original JSON before Alloy's raw-value projection,
   preserving unsigned document numbers and retaining safe native RPC causes.
4. **Review, accounting and publication.** The inventory now records all 22
   dispositions and 45 remaining baseline reader files. Rekor joins the clock
   gate without an ambient-clock exception. Independent review, qualification
   and publication results are recorded in the linked evidence as they finish.

The [plan](../superpowers/plans/2026-10-01-economy-authority-readers.md),
[reader contracts](artifacts/2026-10-01-economy-authority-readers/reviewed-readers.json),
[supporting owners](artifacts/2026-10-01-economy-authority-readers/supporting-owners.json)
and [terminal evidence](artifacts/2026-10-01-economy-authority-readers/)
separate implementation from qualification.

## Contract decisions

- Keep native, external I-JSON and unsigned document contracts separate. A
  regression test caught the initial over-restriction of JSON-RPC `0.10`
  metadata; the final transport gate uses unsigned document semantics before
  projecting the same original bytes through Alloy.
- Preserve the exact digest of caller-owned predicate output even when parsing
  rejects its size. The parser budget prevents projection/allocation; hashing
  still costs time proportional to caller-owned bytes, and an oversized value
  cannot receive a Passed verdict.
- Treat CCIP's embedded test fixture as such. Shape parsing alone never grants
  settlement, signer or replay authority.
- Continue in the existing isolated worktree and publish only the authorized
  security source/evidence. Existing machine-local output links and unrelated
  historical worktrees remain outside the clarified scope.

## Qualification boundary

Terminal failed attempts are retained, including test-fixture compile errors,
expected regression failures and old error-variant assertions. The qualification
record will identify accepted runs and source hashes; a failed attempt is not
counted as passing. The dependency change adds only the existing workspace
`chio-security-types` edge to `chio-anchor`; package versions are unchanged.

This batch does not establish full-workspace, native Firecracker, live-provider,
optional backend, hosted exact-candidate, supply-chain, M5, merge or release
acceptance. Rekor retains its existing endpoint configuration model; threading a
production HttpEgressContract through that client remains separate egress work.
Broader semantic error taxonomy, arithmetic ownership and clock debt remain in
the overall roadmap.

## Next substantial batch

Execute all **23 core, kernel and SDK readers** pinned in
[next-readers.json](artifacts/2026-10-01-economy-authority-readers/next-readers.json):

- Core adversarial/supervisor ingestion (2 readers).
- Browser/mobile kernels, process persistence/mailboxes/nonces/children/worker,
  runtime harness and proof parity (12 readers).
- Binding helpers, Rust/C++ FFI, receipt evaluation and guard SDK glue (9 readers).

Preserve portable/native wire contracts, bound original data before projection,
retain native causes and explicit authority owners, and test process replay,
identity and FFI failure behavior through their real consumers. Dispose concrete
clock, accounting and lifecycle defects found at those boundaries. That leaves
22 baseline observability, product and tooling readers plus the independent
arithmetic, negative-assertion, schema, formal/runtime, retention, supply-chain
and launch gates in the [remaining-work queue](2026-09-28-remaining-security-work.md).
