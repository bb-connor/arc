# Phase 54: Credential Status, Revocation, and Distribution Contracts - Context

## Goal

Make passport lifecycle status, revocation, supersession, and holder-facing
distribution semantics portable to external wallet and verifier ecosystems
without weakening ARC's existing truth model.

## Why This Phase Exists

Phase 53 added one OID4VCI-compatible issuance lane for the existing
`AgentPassport` artifact, but issuance alone is not enough. External holders
and verifiers also need a stable way to learn whether an issued passport is
still current, revoked, or superseded. Today ARC already has local and
trust-control lifecycle publication and resolution, but those semantics are
still mostly ARC-native.

## Locked Decisions

- Preserve the existing `AgentPassport` artifact as the signed credential truth.
- Preserve `did:arc` as the issuer and subject identity inside delivered
  credentials.
- Treat portable status as a projection layered over existing lifecycle truth,
  not as a second mutable authority that can contradict the lifecycle registry.
- Keep the rollout conservative and operator-bounded: no public global
  registry, no synthetic federation, and no silent authority widening.
- Keep supersession explicit. If an external-compatible status surface cannot
  express full ARC lifecycle meaning by itself, ARC must publish an additional
  ARC-native document or reference rather than silently collapsing
  `superseded` into a healthier or less precise state.

## Working Assumptions

- The existing `PassportStatusRegistry` and `PassportLifecycleRecord` are the
  canonical mutable truth source for current passport lifecycle state.
- The best conservative external status primitive is a W3C
  Bitstring Status List v1.0 style publication, because it is standards-legible
  for wallets/verifiers while ARC can continue publishing richer lifecycle
  resolution for supersession and provenance.
- Portable status will likely need two layers:
  1. an external-compatible revocation/suspension signal
  2. an ARC lifecycle resolution reference for richer semantics like
     `superseded_by`
- The issuance flow from phase 53 should eventually surface distribution hints
  so a holder can discover where lifecycle status is published.

## Out Of Scope

- Holder presentation transport and wallet import semantics beyond lifecycle
  distribution hints. That is phase 55.
- External verifier or wallet compatibility proof. That is phase 56.
- Global discovery, marketplace semantics, or generic non-ARC credential
  formats.

## Existing Substrate

- `crates/arc-credentials/src/passport.rs`
  Current portable passport, lifecycle, and distribution types.
- `crates/arc-cli/src/passport_verifier.rs`
  File-backed lifecycle registry with `active`, `superseded`, `revoked`, and
  `notFound` semantics.
- `crates/arc-cli/src/passport.rs`
  Local CLI for lifecycle publish/list/get/resolve/revoke and phase-53
  issuance commands.
- `crates/arc-cli/src/trust_control.rs`
  Remote lifecycle publish/list/get/resolve/revoke and phase-53 issuance
  endpoints.
- `docs/AGENT_PASSPORT_GUIDE.md`
  Current operator/user contract for lifecycle and issuance.
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
  Current portable-trust boundary doc.
- `spec/PROTOCOL.md`
  Current protocol contract for portable trust and issuance.

## Research References

- `docs/research/DEEP_RESEARCH_1.md`
  Rationale for DID/VC issuance plus revocation/status as part of the passport
  portability layer.
- W3C Bitstring Status List v1.0 Recommendation, 15 May 2025
  External-compatible status publication primitive for VC ecosystems.

## Questions To Answer In This Phase

- What exact external-compatible status shape should ARC publish for issued
  passports?
- How should ARC represent `superseded` without losing fidelity or lying to
  wallets that only understand a boolean-ish revocation status?
- Where should distribution metadata live so a holder or verifier can discover
  lifecycle status from an issued passport or issuance response?
- What fail-closed behavior should ARC enforce when lifecycle publication is
  missing, stale, or contradictory?
