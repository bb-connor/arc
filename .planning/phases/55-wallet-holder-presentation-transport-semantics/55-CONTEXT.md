# Phase 55: Wallet / Holder Presentation Transport Semantics - Context

## Goal

Define conservative holder-facing transport semantics for ARC passport
presentation so holders and remote relying parties can exchange challenge and
response material without requiring raw file handoff.

## Why This Phase Exists

Phases 53 and 54 now cover:

- OID4VCI-compatible passport issuance
- portable lifecycle distribution and public lifecycle resolution

But presentation is still mostly file-based:

- a verifier creates a challenge JSON file
- the holder reads that file locally
- the holder produces a response JSON file
- the verifier verifies that file locally or through an authenticated admin
  route

That is enough for ARC-native testing and operator workflows, but it is not a
usable holder transport story for wallets or remote relying parties.

## Locked Decisions

- Preserve the existing signed `arc.agent-passport-presentation-challenge.v1`
  and `arc.agent-passport-presentation-response.v1` artifacts as the portable
  challenge and response truth.
- Preserve `did:arc` as the holder binding inside response proof material.
- Reuse the existing verifier challenge store as the replay and challenge
  truth source rather than inventing a second presentation-state store.
- Keep the transport conservative and operator-scoped:
  - no global wallet network
  - no synthetic verifier discovery
  - no silent widening from public fetch into public mutation
- Keep phase 55 focused on holder transport and submission semantics, not on
  broader external verifier qualification. That is phase 56.

## Working Assumptions

- The current `PassportVerifierChallengeStore` is the right durable substrate
  for public challenge retrieval because it already registers challenge ids,
  expiry, and replay-safe consumption state.
- The likely missing transport layer is a typed ARC-specific presentation
  transport sidecar that points to:
  1. a holder-safe challenge fetch URL
  2. a holder-safe response submission URL
- `passport challenge respond` should be able to fetch a challenge from a URL
  instead of only reading a local file.
- `trust-control` should be able to verify a submitted response against a
  stored challenge without requiring the holder to possess an admin token.

## Out Of Scope

- Generic OID4VP, SD-JWT presentation, or wallet qualification claims.
- Non-ARC credential presentation formats.
- External verifier compatibility proof beyond one ARC transport contract.
- Global verifier discovery or any public mutable registry.

## Existing Substrate

- `crates/arc-credentials/src/challenge.rs`
  current signed challenge contract and validation
- `crates/arc-credentials/src/presentation.rs`
  current signed holder response contract and verification
- `crates/arc-cli/src/passport.rs`
  local challenge create/respond/verify CLI flow
- `crates/arc-cli/src/trust_control.rs`
  remote challenge create/verify routes using the verifier challenge store
- `crates/arc-cli/src/passport_verifier.rs`
  `PassportVerifierChallengeStore` with durable replay-safe challenge state
- `docs/AGENT_PASSPORT_GUIDE.md`
  current file-based presentation contract and explicitly deferred wallet
  transport semantics

## Research References

- `docs/research/DEEP_RESEARCH_1.md`
  wallet-mediated passport portability and verifier-interop motivation
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
  conservative no-global-registry and no-silent-authority-widening boundary
- `spec/PROTOCOL.md`
  current passport presentation and still-deferred wallet semantics boundary

## Questions To Answer In This Phase

- What typed transport sidecar should ARC expose so a holder can discover
  where to fetch a challenge and where to submit a response?
- Which challenge and verification surfaces should become public read or
  public submit routes, and which must remain admin-only?
- How should ARC fail closed on missing challenge ids, stale challenges,
  missing holder proof, or mismatched stored challenge state?
- How should CLI holder workflows map onto the new transport without breaking
  the existing file-based flow?
