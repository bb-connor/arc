---
phase: 377-acp-live-path-cryptographic-enforcement
milestone: v3.12
created: 2026-04-14
status: in_progress
---

# Phase 377 Context

## Goal

Make ACP filesystem and terminal operations actually enforce kernel-validated
capability tokens on the live path, with signature verification and fail-closed
behavior.

## Current Reality

- `arc-acp-proxy` already exposes `CapabilityChecker` and
  `KernelCapabilityChecker`, but the live fs/terminal interception paths still
  only run the built-in allowlist guards.
- `KernelCapabilityChecker` currently parses tokens, checks time bounds, and
  matches scope, but it does not verify the signature or confirm the token was
  issued by the trusted kernel key.
- ACP audit entries and the kernel-backed signer still fabricate
  `capability_id` from the session ID instead of carrying the validated token
  ID from live enforcement.
- The crate already has strong unit coverage for guards, proxy plumbing, token
  parsing, and receipt signing, so this phase can land with focused regression
  tests instead of a broad test harness rewrite.

## Boundaries

- Keep the phase scoped to `arc-acp-proxy` and its direct attestation surfaces.
- Do not broaden into the outward `arc-acp-edge` kernel mediation work yet;
  that belongs to phase `378`.
- Preserve the existing defense-in-depth model: checker allow must still flow
  through the built-in fs/terminal guards.
- Avoid speculative protocol redesign for ACP token transport. Support the
  current live path with additive parsing and fail-closed behavior.

## Key Risks

- ACP fs/terminal params do not currently type a capability-token field, so the
  implementation must extract token material additively from raw JSON without
  breaking existing callers.
- If session/update audit entries keep a fake session-derived capability ID,
  the phase would appear green while still failing the credibility goal.
- If the checker returns an allow verdict without a concrete capability ID, the
  proxy could silently claim cryptographic enforcement without traceability.

## Decision

Execute phase `377` in one narrow vertical slice:

1. Wire live fs/terminal interceptors to consult `CapabilityChecker` before the
   built-in guards, extracting capability tokens from additive ACP params and
   denying on checker deny/error.
2. Strengthen `KernelCapabilityChecker` to verify the token signature against
   trusted kernel material before time/scope evaluation.
3. Carry the validated `capability_id` into ACP audit metadata and kernel
   receipt signing inputs so live-path enforcement is traceable in artifacts.
