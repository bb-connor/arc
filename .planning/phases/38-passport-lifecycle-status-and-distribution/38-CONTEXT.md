# Phase 38 Context

## Goal

Make Agent Passport status, revocation, supersession, and distribution
semantics first-class for relying parties and operators.

## Current Code Reality

- ARC already issues passports, creates verifier policies, and supports
  challenge-bound presentation flows.
- Multi-issuer composition exists, but lifecycle state remains mostly implicit:
  relying parties can verify a passport object, yet there is no supported
  status/distribution contract for active, revoked, or superseded passports.
- `arc-cli` has verifier-policy registry plumbing that can likely host or
  inspire lifecycle state and distribution surfaces.
- Cross-org discovery and reputation-sharing work in later phases require a
  first-class answer to "which passport should a relying party trust right now?"

## Decisions For This Phase

- Treat lifecycle state as a first-class portable-trust concern, not just an
  operator-side convention.
- Keep verifiers fail-closed on unknown, revoked, or superseded state when the
  chosen policy requires lifecycle enforcement.
- Distribution semantics should be explicit enough for relying parties to fetch
  or cache status without inventing private side channels.
- Historical signed passports remain valid artifacts even when newer lifecycle
  state supersedes them.

## Risks

- Supersession can become ambiguous when multiple issuers publish credentials
  for one subject.
- Revocation can accidentally rewrite the truth of historical verification if
  lifecycle semantics are mixed with artifact history.
- Distribution and cache behavior can drift between CLI and verifier code.

## Phase 38 Execution Shape

- 38-01: define lifecycle state and distribution contracts
- 38-02: implement lifecycle management plus verifier enforcement
- 38-03: add docs and regression coverage for lifecycle flows
