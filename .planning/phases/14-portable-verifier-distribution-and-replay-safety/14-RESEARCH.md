# Phase 14: Portable Verifier Distribution and Replay Safety - Research

**Researched:** 2026-03-24
**Domain:** Rust signed verifier artifacts, replay-safe challenge persistence,
local and remote verifier API parity
**Confidence:** HIGH

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| VER-01 | Verifier policy can be created, signed, distributed, and referenced as a reusable artifact instead of only embedded inline in a challenge | Signed verifier policy body/document model, file-backed registry, CLI/admin CRUD, and policy-reference semantics identified |
| VER-02 | Verifier challenge replay state is persisted and enforced so consumed challenges cannot be replayed across processes or restarts | SQLite-backed challenge store, canonical challenge hashing, state transitions, and replay failure paths identified |
| VER-03 | Challenge create/respond/verify flows work consistently across local CLI and remote verifier surfaces with explicit transport and state semantics | Shared request/response types, local/remote command parity, and integration tests across CLI and trust-control identified |

</phase_requirements>

## Summary

Phase 14 should be implemented as a thin verifier-infrastructure layer around
the existing passport alpha rather than a new protocol family. The best seam is
to keep verifier policy semantics in `arc-credentials`, add durable storage and
policy-reference helpers in `arc-cli`, and then expose the same contract over
trust-control for remote relying parties.

The critical design constraint is that replay safety must bind to the exact
challenge payload, not only a challenge ID. A stored row keyed by challenge ID
plus a canonical hash of the full challenge JSON prevents an attacker from
swapping verifier, policy, or disclosure hints while reusing the same ID.

The second critical constraint is that policy references must stay verifier
bound. A policy reference is only safe when the resolved signed policy names
the same verifier as the challenge and remains within its signed validity
window. That check belongs on both the local and remote verifier paths.

## Recommended Architecture

### Signed Verifier Policy Artifacts
- Add signed verifier policy document types to `arc-credentials`
- Verify schema, signer signature, validity window, and required IDs there
- Use a versioned JSON registry in `arc-cli` for durable local and remote
  storage

### Replay-Safe Challenge Store
- Use SQLite in `arc-cli` because the verifier state must survive restarts and
  fits existing local operator deployment patterns
- Store:
  - `challenge_id`
  - verifier
  - nonce
  - optional `policy_id`
  - canonical `challenge_hash`
  - full serialized challenge JSON
  - issued and expiry timestamps
  - explicit status plus optional `consumed_at`
- Enforce transitions in a transaction so one-time consumption is atomic

### CLI and Trust-Control Parity
- Local CLI:
  - `passport policy create|verify|list|get|upsert|delete`
  - `passport challenge create|verify` with
    `--verifier-policies-file` and `--verifier-challenge-db`
- Remote trust-control:
  - verifier policy CRUD endpoints
  - remote challenge create and verify endpoints
  - federated issue reuses the same stored verifier-policy and replay-safe
    challenge semantics

### Reporting Contract
- Include `challengeId`, `policyId`, `policySource`, `policyEvaluated`, and
  `replayState` in challenge verification results
- Preserve those fields through federated issue so operators can debug policy
  source and replay-state behavior from one output

## Primary Risks

### Risk 1: Stored policy reference without verifier binding
If the resolved policy can be reused for a different verifier, a policy created
for one relying party could be replayed against another. Mitigation: require the
signed policy's `verifier` to match the challenge verifier exactly.

### Risk 2: Challenge ID reuse with mutated payload
If storage only keys on `challengeId`, a replay could reuse a known ID while
swapping policy or verifier fields. Mitigation: bind the stored row to a hash of
the full challenge payload and reject hash mismatches.

### Risk 3: Remote verifier surfaces drift from local semantics
If trust-control challenge creation or verification accepts different policy or
replay rules, operators will not know which semantics apply. Mitigation: reuse
shared request/response types and integration tests that hit both local and
remote paths.

## Validation Strategy

- Local file-backed verifier policy reference plus replay-safe verification:
  `cargo test -p arc-cli --test passport -- --nocapture`
- Remote trust-control replay-safe verifier issue path:
  `cargo test -p arc-cli --test federated_issue -- --nocapture`
- Remote verifier policy admin CRUD:
  `cargo test -p arc-cli --test provider_admin -- --nocapture`

## Conclusion

The shipped implementation path is coherent: signed verifier policies live in
`arc-credentials`, durable registry and replay-state storage live in
`arc-cli`, and trust-control exposes the same semantics remotely without
inventing a second verifier model.
