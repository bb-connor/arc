# CLI authority and proof readers execution

Date: September 30, 2026. Base: `943482d2cb82a1cf466584b47aee6b509c921d90`.
Branch: `packet/3-retention-accounting`, worktree `/tmp/arc-security-launch`.
Scope: the [26-reader plan](../superpowers/plans/2026-09-30-cli-authority-proof-readers.md).
This is local implementation and focused qualification, not hosted or release acceptance.

## Delivered contracts

- [x] Shared input owners: actual-byte bounded regular-file and stream reads;
  duplicate-aware native JSON preserving full-width integers; a separate exact
  canonical I-JSON contract; explicit JSON/YAML selection; bounded YAML expansion,
  nesting and nodes; duplicate/non-string key rejection; literal enum arguments;
  retained typed parser causes with stable public rendering.
- [x] Authority, admin, runtime, certificate and passport readers: strict original
  documents before existing signer/authority verification. Signing custody is
  existing-only, private, singly linked, owned by the effective user and checked
  for identity changes. Fixed-capacity secret buffers are zeroized on every exit.
  Read-only trust and issuer-metadata queries cannot provision missing keys.
  Certificate queries select exact signed session metadata independently of
  capability IDs, bound database text before Rust materialization and enforce
  count/byte/sequence limits. Passport HTTP input is bounded; signed-policy
  failures cannot fall back to bare policy. Clock faults/rollback and zero or
  overflowing deadlines reject.
- [x] Current manifest schema only: removed the v1 converter, conversion result,
  legacy permission amendment API, CLI conversion branch and associated SDK
  error adapters. Authentic obsolete-v1 input is negative test data. Current-v2
  signature, registry and permission validation remain intact.
- [x] Proof collection, assembly, export, doctor, environment, risk, explanation
  and fixtures: original reads and copies are bounded. Collections share entry,
  depth and actual-byte budgets; repeated commerce references charge every
  retained copy and receipt candidates are scanned once. Export verifies a
  private captured tree, packages those same bytes, and re-verifies signed public
  redaction before archive creation. Explanation reads captured evidence and
  remaps only displayed paths. Snapshot namespaces count parent directories and
  reject collisions before writes. Catalog IDs are bounded unique names, and
  destination checks precede directory removal. Settlement RPC responses bind
  protocol, request ID and result/error shape before evidence projection.
- [x] Trust, credit, liability, receipt explanation, appraisal and underwriting:
  bounded original input and explicit policy formats preserve existing signed
  authority checks. Diagnostic classification stays separate from authentication.
- [x] Semantic inventory: all 26 selected baseline readers have explicit
  [per-file dispositions](artifacts/2026-09-30-cli-authority-proof-readers/reviewed-readers.json),
  with [supporting owners](artifacts/2026-09-30-cli-authority-proof-readers/supporting-owners.json).
  Removing the manifest converter also retires that additional baseline owner:
  the workspace lexical baseline falls from 250 to **223**, with **29** CLI
  baseline files remaining. These are review-debt counts, not vulnerability counts.

Default limits are 16 MiB per document, 128 MiB per collection, 4,096 entries and
64 path levels. Tighter existing owner limits remain, including 1 MiB stored
certificate receipts and 64/256 KiB finding authority documents. Active-response
bundles retain their explicit 64 MiB owner limit. YAML permits one document,
100,000 expanded nodes, depth 64 and 16 MiB expanded string bytes. Remote passport
requests have a 30-second timeout. Limits do not confer authority.

## Review and qualification

Implementation was inline, followed by one independent whole-batch review. Its
nine findings were repaired: catalog path deletion, repeated commerce allocation,
certificate session selection, read-only key creation, pre-limit policy copying,
JSON-RPC response binding, secret-buffer reallocation, temporary explanation
paths, and Windows directory synchronization. The explanation repair keeps reads
on captured bytes while changing presentation paths only. Directory syncing is
Unix-specific; regular files sync on every platform.

Integration qualification also exposed loss of actionable public proof reasons
in the earlier typed-source adapter. The adapter now pairs native causes with
static public diagnostics and registered categories, preserving integrity/schema
exit codes while withholding rejected input. A source-chain and redaction control
covers this mapping. Commerce, risk, runtime-regeneration and local-family
verification retain concrete native causes through proof-room, allowing safe
owner-defined public reasons instead of flattening those failures to strings. The production snapshot owner now declares its temporary
storage dependency outside dev-dependencies.

Final focused validation passes **254 tests**: 92 CLI unit cases, 129 real-CLI
proof integration cases, 25 manifest-v2 cases and 8 SDK vector cases. The SDK's
8 regeneration helpers remain ignored; 18 unrelated proof-server cases are
outside these filters. Formatting, file hygiene, trust boundaries, clocks,
accounting, negative assertions and wire-schema ratchets pass. The schema
snapshot records removal of the obsolete manifest-v1 declaration.

Terminal logs and source identities are recorded in the
[artifact index](artifacts/2026-09-30-cli-authority-proof-readers/README.md).
Build attempts and initial failing tests are retained alongside final results.
No workspace-wide build or lint campaign was run.

The source ratchets retain their configured scope. A passing accounting ratchet
does not close the separate 85 pending semantic arithmetic entries. Hostile
concurrent ancestor mutation, downstream cryptographic correctness, remaining
product/protocol readers, native platform campaigns and exact-candidate hosted/M5
acceptance remain separate boundaries. This batch performs no push, merge,
release, publication or external activation.

## Next substantial chunk

Execute the [remaining 29 CLI baseline readers](artifacts/2026-09-30-cli-authority-proof-readers/next-readers.json):

1. Finding challenge/hosted/operator/status-floor/verified-fix/verification and
   attestation/workflow readers. Bind signed authority, deployment pins and
   retained status before any effect; review clock/deadline and error semantics.
2. Buyer/treaty and pheromone directory, relay, delivery, runtime, mount and
   assurance package/archive readers. Bound original documents, collections and
   archive namespaces; preserve canonical custody and authenticated identity.
3. MCP provision/discovery/cage/wrap, CLI runtime, lineage and market readers.
   Preserve enforcing-host requirements and current-only schemas; dispose each
   decoder semantically and add focused production-path negative controls.
4. Reconcile the remaining reader/clock/arithmetic inventory with the concrete
   code changes and qualify only the changed owner boundaries.

The broader roadmap still includes other protocol/product owners, structural
and declaration work, retention acceptance, sanitizer/formal correspondence,
supply-chain source audits, and exact-candidate hosted/M5 delivery.
