# Phase 56: External Verifier Interop and Compatibility Qualification - Context

## Goal

Prove one external non-CLI verifier or holder path end-to-end over the shipped
ARC portable-credential surfaces, then close `v2.11` with explicit
qualification and partner-facing evidence.

## Why This Phase Exists

Phases 53 through 55 now ship:

- OID4VCI-compatible passport issuance
- portable lifecycle distribution and public lifecycle resolution
- holder-facing public challenge fetch and public response submit transport

That means ARC has a credible portable credential substrate, but it still
needs one concrete "external client can really do this" proof so `v2.11`
doesn't remain a standards-alignment claim without an interoperability lane.

## Locked Decisions

- Prove one narrow external client path instead of claiming broad wallet
  ecosystem support.
- Use raw HTTP plus the existing ARC JSON artifacts as the interop fixture.
- Preserve ARC-native trust anchors:
  - delivered credentials remain `did:arc`-bound `AgentPassport` artifacts
  - presentation still uses the existing signed ARC challenge and response
  - lifecycle and verifier replay truth stay operator-scoped
- Keep partner and release docs explicit about what is still out of scope:
  generic OID4VP, DIDComm, SD-JWT, public verifier discovery, and global trust
  semantics.

## Existing Substrate

- `crates/arc-credentials/src/oid4vci.rs`
  OID4VCI-compatible issuer metadata, offers, token requests, and credential
  responses
- `crates/arc-cli/src/trust_control.rs`
  remote issuance endpoints plus public holder challenge fetch/submit routes
- `crates/arc-cli/tests/passport.rs`
  local and remote issuance, lifecycle, and holder-transport regression lanes
- `docs/AGENT_PASSPORT_GUIDE.md`
  operator-facing portable passport docs
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
  conservative portability boundary

## Research References

- `docs/research/DEEP_RESEARCH_1.md`
  on OID4VCI and later passport portability as an ecosystem bridge, while
  keeping 2026 adoption claims pragmatic
- `.planning/phases/55-wallet-holder-presentation-transport-semantics/55-RESEARCH.md`
  on keeping holder transport ARC-native and challenge-bound before making any
  broader verifier compatibility claim

## Questions To Answer In This Phase

- What is the narrowest external client proof that still counts as real
  interoperability?
- Which release and partner docs need to change so ARC doesn't overclaim broad
  wallet compatibility?
- What evidence closes `VC-04` while preserving `VC-05`?
