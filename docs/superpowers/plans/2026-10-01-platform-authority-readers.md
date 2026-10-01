# Platform authority reader implementation plan

> Implement inline with `superpowers:executing-plans`. The user authorized the
> complete next batch and publication on October 1. Preserve existing evidence.

**Goal:** Dispose all 31 platform readers pinned by the guard/security handoff,
repairing original-input, authority, durable-state and rejection contracts.

**Architecture:** Reuse `UntrustedJsonText` at each original byte boundary.
Native signed integers retain their full range; strict canonical owners retain
byte equality. Parsing does not replace signature, tenant, replay or effect
authority. Keep helpers within the owning crate and native causes behind safe
public diagnostics.

**Spec:** `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md`,
mechanisms A/B/C; `docs/security/signed-json-boundaries.md`;
`docs/reviews/2026-09-28-remaining-security-work.md`, item 2.

**Base:** `377ee5b773eff424d12182682b411867b4d643be` in
`/tmp/arc-security-launch`, branch `packet/3-retention-accounting`.

## Constraints

- The 31 paths are pinned in the preceding guard batch's `next-readers.json`.
- Retain native integer, signing, schema and canonical-byte contracts.
- Enforce per-document bounds before projection and cumulative bounds where
  an entry point retains a collection. Do not add compatibility fallback.
- Preserve native error causes; public display and HTTP errors redact input.
- Qualify changed packages and direct consumers. Full workspace, native runner,
  live provider, hosted, scale, M5 and release acceptance remain separate.
- Preserve machine-local output links and old conflict experiments. Commit
  unfinished security snapshots separately as WIP, without qualification claims.

## Review focus

1. Duplicate keys hidden inside ignored nested fields before typed decoding.
2. Full-width native integers and valid unsigned floating-point representations.
3. Stored canonical payloads or worker results substituted across identities.
4. Oversized graph/artifact collections and cumulative verification work.
5. Causes lost or attacker-controlled content exposed through public errors.

### Task 1: HTTP authority and transaction evidence

**Files:** The four pinned `chio-http-core` readers and six pinned
`chio-transaction-passport` readers, their error/input owners and tests.

**Interfaces:** Consume `UntrustedJsonText::from_wire`, `decode_signed`, and
`decode_canonical`; provide a bounded transaction-artifact parser with a native
`SharedUntrustedJsonError` cause for its dependent evidence crates.

- [x] Add original duplicate, oversize, numeric and redaction regressions at
  actual public parser/handler boundaries; preserve legitimate positive cases.
- [x] Run focused regressions and retain their initial terminal evidence.
- [x] Implement bounded original decoding, shared causes, HTTP-safe errors and
  relevant authority clock ownership. Preserve handler authorization ordering.
- [x] Run owning packages and consumer compilation; inspect terminal results.

### Task 2: Commerce and exported evidence

**Files:** The thirteen pinned readers in `chio-commerce-order`,
`chio-agent-web-interop`, `chio-enterprise-export`, and `chio-trust-market-context`.

**Interfaces:** Consume Task 1's transaction input contract where these crates
already share `TransactionPassportError`. Commerce keeps its own error owner.

- [x] Add duplicate and bounded-input controls to the actual evidence readers.
- [x] Migrate every original decoder, retaining typed projections only after
  original validation; enforce evidence collection budgets and claim custody.
- [x] Verify positive fixtures, wrong-authority/replay controls and native
  error sources in all four owning packages.

### Task 3: Hosted ingress, workers and PostgreSQL

**Files:** Eight pinned hosted-edge, finding-worker and PostgreSQL readers;
their existing validation/error owners and production-linked tests.

**Interfaces:** Retain current canonical ingress and tenant transactions;
introduce typed local input/protocol errors without changing persisted identity.

- [x] Exercise bounded original worker/job/state input and precise rejection.
- [x] Retain canonical inputs already checked and repair readback paths that
  trust stored projection bytes without validating their owning contract.
- [x] Preserve worker request/result binding, tenant scope, replay and clock
  ownership. Reject malformed input before durable writes or output delivery.
- [x] Qualify package tests, supported local PostgreSQL tests and consumers;
  distinguish unavailable external execution from completed checks.

### Task 4: Review, inventory and publication

- [x] Run one fresh independent review of the full batch; reproduce and fix
  material findings, with focused post-fix checks.
- [x] Record all 31 semantic dispositions and supporting owners; update the
  inventory and remaining queue. Counts are review debt, not vulnerability counts.
- [x] Run source/format/inventory gates, preserve failures and exact identities,
  and commit/push the final scoped implementation and evidence.

## Execution record

The tracked execution ledger and evidence belong under
`docs/reviews/artifacts/2026-10-01-platform-authority-readers/`.
The [execution report](../../reviews/2026-10-01-platform-authority-readers-execution.md)
and its qualification record state each task's actual terminal result.
