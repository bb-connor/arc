---
phase: 391-authoritative-edge-unification
milestone: v3.13
created: 2026-04-14
status: completed
---

# Phase 391 Context

## Goal

Finish authoritative edge unification by moving ACP live-path capability
enforcement onto a real kernel-backed guard path and quarantining the
remaining non-authoritative A2A/ACP compatibility helpers away from the
default runtime surfaces.

## Current Reality

- Phase `390` landed `arc-cross-protocol` and moved the default authoritative
  A2A and ACP outward invocation paths onto `CrossProtocolOrchestrator`.
- `crates/arc-acp-proxy/src/kernel_checker.rs` still performed local token
  parsing, signature verification, time-bound checks, and bespoke scope
  matching against ACP filesystem and terminal operations. That meant the live
  ACP guard decision was still split away from the shared orchestrated kernel
  substrate.
- `crates/arc-a2a-edge/src/lib.rs` and `crates/arc-acp-edge/src/lib.rs` still
  exposed public passthrough helpers directly on the main edge types, which
  made non-authoritative direct invocation paths too easy to treat as part of
  the primary runtime surface.
- ACP permission preview metadata already said `authoritative: false`, but it
  did not yet carry explicit negative claim semantics (`previewOnly`,
  `receiptBearing: false`, `claimEligible: false`) that made the non-goal
  machine-readable.

## Boundaries

- Keep this phase scoped to authority-path correctness and surface quarantine.
  Do not broaden it into fidelity semantics (`392`) or late-v3 ledger/docs
  reconciliation (`393`).
- Preserve compatibility behavior for tests and bounded migrations, but move
  it behind explicit compatibility accessors so the public runtime story is no
  longer ambiguous.
- Reuse the shared `arc-cross-protocol` substrate rather than creating another
  ACP-only authority implementation.

## Key Risks

- If ACP live-path checks still rely on local verifier logic, ARC will keep a
  split-authority seam exactly where the review said the system was weakest.
- If compatibility helpers remain public on the main edge types, operators and
  future code can continue to mistake passthrough flows for authoritative
  execution even when metadata says otherwise.
- If permission preview and compatibility metadata do not explicitly encode
  their non-authoritative status, later claim-qualification work will still
  need bespoke caveat logic.

## Decision

Complete phase `391` in one execution slice:

1. Replace ACP proxy token-only checking with a kernel-backed authoritative
   checker that uses `CrossProtocolOrchestrator` plus a guard-only registered
   authority server to emit real allow/deny receipts without duplicating the
   ACP side effect.
2. Carry the authorization receipt reference into ACP audit context so live
   session/update observations can correlate back to the authoritative guard
   decision.
3. Move A2A and ACP passthrough APIs behind explicit `.compatibility()`
   surfaces and enrich passthrough/preview metadata with explicit
   `compatibilityOnly` / `previewOnly`, `receiptBearing: false`, and
   `claimEligible: false` markers.
4. Prove the new boundary with crate-local tests covering authoritative ACP
   guard behavior and the quarantined compatibility APIs.
