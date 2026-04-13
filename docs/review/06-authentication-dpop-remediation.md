# Hole 06 Remediation Memo: Authentication, DPoP, and Subject Binding

## Problem

ARC currently makes stronger claims about stolen-capability resistance, proof-of-possession, and caller identity continuity than the code enforces.

The public claim is explicit: `README.md:240` says DPoP binds tokens to the agent keypair so "a stolen capability is worthless without the corresponding private key." The current implementation does not justify that claim end to end:

- Capability use only requires DPoP when the matched grant sets `dpop_required == Some(true)` in `crates/arc-core-types/src/capability.rs:924-927`.
- Kernel subject binding is an equality check between `cap.subject.to_hex()` and caller-supplied `request.agent_id` in `crates/arc-kernel/src/request_matching.rs:175-187`.
- Session reuse on the hosted HTTP edge compares only transport plus a narrow identity tuple in `crates/arc-cli/src/remote_mcp.rs:5111-5166`.
- DPoP replay protection is an in-memory LRU cache in `crates/arc-kernel/src/dpop.rs:135-192`, with the same pattern reused on the hosted edge in `crates/arc-cli/src/remote_mcp.rs:4181-4228`.
- The spec promises stronger HTTP DPoP behavior, including `jti`, `htm`, and `htu` checks, in `spec/PROTOCOL.md:654-666`, but the shipped ARC-native proof format does not even contain those fields.

The result is a mixed model:

- Some flows are sender-constrained.
- Some flows are only identity-labeled.
- Some flows derive a stable internal agent key.
- Some flows generate a random per-session key.
- Session reuse can survive authorization shrink for the same principal.

That is not enough to defend strong claims about stolen-token uselessness, universal proof-of-possession, or continuity of authenticated caller identity.

## Current Evidence

There is real security machinery here already.

- The kernel has native DPoP proof verification and verifies proof schema, sender key, capability id, tool target, argument hash, freshness, signature, and nonce reuse in `crates/arc-kernel/src/dpop.rs:1-220`.
- The kernel has passing tests for DPoP-required grants:
  - valid proof allows in `crates/arc-kernel/src/lib.rs:11667-11696`
  - missing proof denies in `crates/arc-kernel/src/lib.rs:11698-11728`
  - mismatched proof binding denies in `crates/arc-kernel/src/lib.rs:11730-11760`
- The hosted HTTP edge already normalizes OAuth enterprise identity into `federatedClaims` and `enterpriseIdentity` in `crates/arc-core-types/src/session.rs:181-205` and `crates/arc-cli/src/remote_mcp.rs:1055-1185`.
- There is a deterministic federated-agent key path when `identity_federation_seed_path` is configured. `derive_session_agent_keypair` uses the normalized principal to derive a stable ARC keypair in `crates/arc-cli/src/remote_mcp.rs:1318-1331`.
- The hosted edge already rejects some session reuse mismatches:
  - auth context validation logic is in `crates/arc-cli/src/remote_mcp.rs:5111-5166`
  - cross-tenant and cross-subject reuse tests exist in `crates/arc-hosted-mcp/tests/session_isolation.rs:35-114`
  - expired or mismatched token reuse is tested in `crates/arc-hosted-mcp/tests/error_contract.rs:141-230`
- OAuth discovery metadata already publishes a sender-constraint story in `crates/arc-cli/src/remote_mcp.rs:6340-6354`.

Those are meaningful foundations. The problem is not "nothing exists." The problem is that the shipped evidence supports a bounded sender-constraint feature, while the docs currently speak as if sender constraint and caller binding are universal and robust across session reuse, failover, and restart.

## Why Claims Overreach

### 1. DPoP is optional, not universal

`ToolGrant.dpop_required` is tri-state optionality, not a global safety invariant. `None` and `Some(false)` explicitly disable DPoP in `crates/arc-core-types/src/capability.rs:924-927`, and the kernel only verifies DPoP if any matching grant requires it in `crates/arc-kernel/src/lib.rs:1914-1926` and `crates/arc-kernel/src/lib.rs:2183-2195`.

That means the current honest claim is:

"Some grants can require proof-of-possession."

It is not:

"Stolen capabilities are useless."

### 2. Subject binding is caller-supplied string matching

The kernel currently binds capability subject to `request.agent_id`, and `request.agent_id` is just a string field on `ToolCallRequest` in `crates/arc-kernel/src/runtime.rs:24-45`. The actual binding check is:

- compute `cap.subject.to_hex()`
- compare it to `agent_id`

in `crates/arc-kernel/src/request_matching.rs:175-187`.

That is not a cryptographic binding by itself. It only becomes meaningful when some upstream transport has already authenticated and locked `agent_id` to the sender. The code and docs do not consistently surface that dependency.

### 3. Hosted session reuse ignores material authorization fields

The hosted edge stores rich OAuth session context:

- `scopes`
- `client_id`
- `tenant_id`
- `organization_id`
- `groups`
- `roles`
- `enterpriseIdentity.subject_key`

in `crates/arc-core-types/src/session.rs:181-275`.

But session reuse validation ignores almost all of that. In `crates/arc-cli/src/remote_mcp.rs:5111-5166`, OAuth reuse is accepted if:

- principal matches
- issuer matches
- subject matches
- audience matches

and nothing else is compared.

That creates a privilege-shrink hole:

- same principal
- same issuer
- same subject
- same audience
- narrower scopes or changed groups/roles/tenant/client context

can still attach to an already-issued session that was created under a broader authorization view.

### 4. Replay robustness is process-local

Both the kernel and hosted-edge sender DPoP paths use in-memory LRU nonce stores:

- kernel: `crates/arc-kernel/src/dpop.rs:135-192`
- hosted HTTP sender DPoP: `crates/arc-cli/src/remote_mcp.rs:4181-4228`

This means replay protection is lost or weakened under:

- process restart
- multi-node deployment without shared replay state
- failover to another node
- cache eviction under pressure

The current design is acceptable for a best-effort single-process sender-constraint feature. It is not enough for a strong replay-resistance claim.

### 5. HTTP DPoP claims are stronger than the shipped proof format

The spec says DPoP-bound protected-resource admission checks nonce, `jti`, `htm`, and `htu` in `spec/PROTOCOL.md:654-666`.

The shipped proof body for ARC-native DPoP is:

- `capability_id`
- `tool_server`
- `tool_name`
- `action_hash`
- `nonce`
- `issued_at`
- `agent_key`

in `crates/arc-kernel/src/dpop.rs:53-75`.

The hosted-edge sender proof verifier in `crates/arc-cli/src/remote_mcp.rs:4181-4228` also checks the ARC-native fields, not RFC 9449 JWT DPoP claims. The discovery metadata further says proof is required only when `matchedGrant.dpopRequired == true` in `crates/arc-cli/src/remote_mcp.rs:6346-6350`.

So the implementation is not yet the protocol the spec describes.

### 6. Agent identity continuity is configuration-dependent and incomplete

When `identity_federation_seed_path` is absent, `derive_session_agent_keypair` falls back to `Keypair::generate()` in `crates/arc-cli/src/remote_mcp.rs:1322-1331`. That means identical enterprise identities do not get a stable ARC subject by default.

Even when deterministic derivation is enabled, it currently keys off normalized principal alone, not the fuller enterprise subject binding or sender key continuity material.

### 7. Static bearer and anonymous modes cannot honestly inherit the strongest claims

Static bearer auth binds a session to a token fingerprint in `crates/arc-cli/src/remote_mcp.rs:5352-5366`. That can support "same bearer token" continuity, but not a proof-of-possession claim unless the bearer itself is sender-constrained at another layer.

Anonymous and unsender-constrained bearer modes should never be described with the same stolen-token or stolen-capability guarantees.

## Target End-State

ARC should target one coherent model:

1. Every claim-bearing remote session is sender-constrained by default.
2. Every capability used in a claim-bearing profile is bound to an authenticated sender key, not just a caller-supplied identifier string.
3. Every session captures a full immutable security context snapshot at initialization.
4. Every session reuse request must either reproduce that snapshot exactly or present an ARC-minted continuation artifact proving an equivalent security context.
5. Replay protection must survive restart and node failover within the configured freshness window.
6. Stable ARC agent identity must derive from a stable enterprise subject binding, not from ad hoc per-session randomness.
7. Privilege shrink or privilege drift must fail closed and force re-initialization plus capability re-issuance.

The honest end-state claim should be:

"In strict sender-constrained mode, a stolen ARC capability, access token, or session id is insufficient to resume authority without the bound sender key and matching session-continuity context."

That claim is materially narrower and more defensible than the current prose.

## Required Auth/Session Changes

### 1. Replace optional DPoP with explicit sender-constraint modes

Deprecate grant-level `Option<bool>` semantics for security-critical deployments.

Introduce a positive sender-constraint contract such as:

```rust
enum SenderConstraintMode {
    RequiredArcInvocationDpop,
    RequiredHttpDpop,
    RequiredMutualTls,
    RequiredHttpDpopPlusArcInvocationDpop,
    LegacyBestEffort,
}
```

Required changes:

- Default all newly issued hosted-session capabilities to a required sender-constraint mode.
- Keep legacy non-PoP capability operation only behind an explicit compatibility profile.
- Tie claim language to mode:
  - strict modes may make stolen-token/stolen-capability claims
  - legacy mode must not

### 2. Stop trusting `ToolCallRequest.agent_id` as the primary subject binder

Refactor the kernel so the authenticated caller arrives as structured security context, not a caller-provided string.

Recommended shape:

```rust
struct AuthenticatedCaller {
    sender_key: PublicKey,
    session_id: Option<SessionId>,
    auth_context_hash: String,
    transport: SessionTransport,
    continuity_mode: SenderConstraintMode,
}
```

Then:

- `cap.subject` must match `AuthenticatedCaller.sender_key`, not `request.agent_id`
- `ToolCallRequest.agent_id` becomes derived metadata or is removed from externally reachable paths
- direct/native invocation APIs must prove possession of the sender key on every capability use unless explicitly marked legacy

This removes the current "string equality" weak point and makes subject binding depend on verified cryptographic continuity.

### 3. Split HTTP sender proof from internal ARC invocation proof

The current implementation conflates two different problems:

- proving possession of the OAuth sender key for the HTTP request
- proving possession of the ARC capability subject key for the internal tool invocation

Those should be modeled separately.

Recommended design:

- Public HTTP boundary:
  - implement RFC 9449 JWT DPoP for OAuth sender-constrained tokens
  - verify `jti`, `htu`, `htm`, `iat`, and access-token binding
  - store replay state in a durable replay store
- Internal ARC invocation boundary:
  - keep or evolve ARC-native invocation DPoP bound to capability id, tool target, and canonical argument hash
  - require it whenever a capability is exercised outside a fully trusted local edge path

For hosted MCP, there are two acceptable end-states:

- Strict end-state A: the edge verifies HTTP DPoP and then synthesizes an internal verified caller context, so the client does not need to generate a second ARC-native proof.
- Strict end-state B: the edge verifies HTTP DPoP and also requires an ARC-native invocation proof for any client that is directly exercising ARC capability semantics.

What should not remain is the current mixed story where the spec describes RFC-style HTTP DPoP but the implementation uses the ARC-native proof shape everywhere.

### 4. Introduce durable replay state

Replace process-local LRU replay protection with a storage-backed interface:

```rust
trait ReplayStore {
    fn insert_if_fresh(&self, namespace: ReplayNamespace, key: ReplayKey, ttl: Duration) -> Result<ReplayVerdict>;
}
```

Replay keys should be scoped by:

- proof family: `http_dpop` or `arc_invocation_dpop`
- sender binding id or token thumbprint
- nonce or `jti`
- target tuple
- capability id when applicable

Operational requirements:

- restart-safe
- shared across nodes for the same protected resource
- TTL eviction
- insert-if-absent semantics
- auditability for replay-denied events

Implementation options:

- SQLite for single-node strict mode
- Postgres or another linearizable shared store for HA mode
- memory cache only as a front cache, never as source of truth

### 5. Capture a full session security snapshot and validate it on reuse

Add a canonical `SessionSecuritySnapshot` captured at initialization. It should include at least:

- transport
- auth method kind
- token fingerprint or token family id
- sender key or mTLS thumbprint
- issuer
- subject
- audience or protected resource id
- scopes
- `client_id`
- `tenant_id`
- `organization_id`
- `groups`
- `roles`
- `enterpriseIdentity.subject_key`
- origin if origin is part of the trust model
- protocol version if session resumption depends on it

Reuse rule:

- exact-match by default
- alternatively, accept an ARC-minted continuation assertion whose embedded snapshot hash equals the stored session snapshot hash

This closes the privilege-shrink hole. A request with changed scopes, changed groups, changed roles, changed tenant, changed client, or changed sender key must not resume the session.

### 6. Make session continuation explicit

If session reuse with refreshed OAuth tokens is a product requirement, do not infer continuity from "same principal."

Instead, mint a signed continuation artifact at initialization:

```rust
struct SessionContinuationAssertion {
    session_id: SessionId,
    auth_context_hash: String,
    sender_key_thumbprint: String,
    issued_capabilities_hash: String,
    issued_at: u64,
    expires_at: u64,
}
```

Rules:

- present it on session resume
- require the same sender key continuity
- reject if the newly authenticated security snapshot differs from the original
- force re-initialization if authorization shrank or expanded

This turns session reuse into a cryptographic continuity contract instead of a heuristic identity match.

### 7. Make ARC agent identity continuity explicit and stable

Today stable agent derivation is opt-in and principal-based. The target should be stronger:

- derive ARC agent identity from enterprise `subject_key` plus provider scope, not just display principal
- optionally bind derivation to sender key thumbprint so that "same human subject, different device key" can be modeled deliberately instead of accidentally
- persist the mapping or make deterministic derivation a required deployment mode for identity-carrying claims

Recommended rules:

- strict identity mode requires deterministic derivation or persisted subject mapping
- random per-session keys remain available only for ephemeral or anonymous compatibility modes
- capabilities issued into a hosted session must name the stable ARC subject for that enterprise identity, not a throwaway key, whenever identity portability or continuity claims are made

### 8. Separate strict mode from compatibility mode in the hosted edge

The hosted edge currently supports:

- static bearer
- JWT bearer
- introspection bearer
- optional sender constraint

These should be split into explicit deployment profiles:

- `strict_sender_constrained`
- `compatibility_bearer`
- `anonymous_local_only`

Only the first profile should support the strong public claims.

### 9. Review `shared_hosted_owner` and cross-session execution isolation

This memo is about authentication and continuity, not process isolation, but session binding claims are harder to defend if multiple sessions share one upstream subprocess in `crates/arc-cli/src/remote_mcp.rs:1983-1990`.

The strict profile should either:

- disable shared-owner multiplexing, or
- prove that sender identity, state, and authorization are partitioned per session even under a shared upstream runtime

Without that, identity continuity can still be undermined by state bleed above the kernel.

## Spec Changes

### 1. Rewrite the verification rule

Update `spec/PROTOCOL.md:291-301` so the required rule is not "DPoP proof is valid when the selected grant requires it."

It should say:

- strict sender-constrained profiles require verified sender proof for every remotely authenticated capability use
- legacy compatibility profiles may allow bearer-only capability exercise, but those profiles do not support stolen-token or stolen-capability resistance claims

### 2. Align hosted-edge DPoP text with the actual protocol

If ARC intends to claim RFC-style OAuth DPoP, the spec must require RFC 9449 semantics on the HTTP boundary:

- `jti`
- `htu`
- `htm`
- `iat`
- access-token confirmation binding

If ARC intends to keep its ARC-native proof shape on the HTTP boundary, the spec must stop claiming RFC-style field checks.

The current mismatch between `spec/PROTOCOL.md:654-666` and `crates/arc-cli/src/remote_mcp.rs:4181-4228` must be removed.

### 3. Add a formal session-continuity section

Document:

- what exact auth context is snapshotted
- when a session may be resumed
- which fields are exact-match
- which changes force re-initialization
- whether token refresh is supported
- how continuation assertions are validated

### 4. Add a strict-mode claim boundary

Update README, DPoP guide, and discovery metadata to distinguish:

- strict sender-constrained mode
- compatibility mode

The stolen-capability claim should only appear under the strict mode description.

### 5. Tighten discovery metadata

The discovery metadata currently says:

- `proofRequiredWhen: "matchedGrant.dpopRequired == true"`

in `crates/arc-cli/src/remote_mcp.rs:6346-6350`.

That should become something like:

- `proofRequiredWhen: "always in strict_sender_constrained profile"`

or the equivalent machine-readable rule.

## Validation Plan

### 1. Unit and integration tests

Add or extend tests for:

- same principal, narrower scopes, same issuer/subject/audience => session reuse denied
- same principal, changed `client_id` => denied
- same principal, changed tenant => denied
- same principal, changed groups => denied
- same principal, changed roles => denied
- same token, different sender key => denied
- same sender key, different session snapshot hash => denied
- stale continuation assertion => denied
- direct capability call with no sender proof in strict mode => denied
- direct capability call with mismatched proof subject => denied

### 2. Replay tests

Add replay suites for:

- same nonce rejected within one process
- same nonce rejected after process restart
- same nonce rejected across two nodes
- same HTTP DPoP `jti` rejected across two nodes
- eviction pressure does not permit immediate replay within TTL

### 3. Failover and chaos tests

Run adversarial tests where:

- session initializes on node A
- replay or resume attempt lands on node B
- sender proof is replayed after node A restart
- privilege-shrunk token attempts to reuse a session minted under a broader token

Strict mode should fail closed in each case.

### 4. Identity continuity tests

Add tests proving:

- same enterprise subject maps to same ARC subject in strict identity mode
- different enterprise subject maps to different ARC subject
- same principal but different provider scope does not alias accidentally
- absence of deterministic identity configuration downgrades the claim boundary

### 5. Protocol conformance tests

Extend conformance to verify:

- strict-mode discovery metadata
- required sender-proof behavior
- session continuation semantics
- refusal to advertise strict-mode guarantees when compatibility mode is enabled

### 6. Documentation verification

Before reintroducing strong claims:

- cross-check README, `docs/DPOP_INTEGRATION_GUIDE.md`, `spec/PROTOCOL.md`, and discovery metadata
- require a release checklist item that all claim text matches the enabled strict-mode behavior

## Milestones

### Milestone 1: Security model cleanup

- Introduce explicit strict vs compatibility auth profiles
- Deprecate grant-level `Option<bool>` semantics for strict deployments
- Rewrite claim language to match profile boundaries

### Milestone 2: Full session snapshot validation

- Add `SessionSecuritySnapshot`
- Enforce exact-match reuse
- Add privilege-shrink regression tests

### Milestone 3: Durable replay infrastructure

- Add replay-store trait
- Implement single-node durable backend
- Implement HA-capable shared backend
- Wire both HTTP sender DPoP and ARC invocation DPoP to it

### Milestone 4: HTTP DPoP and continuation hardening

- Implement real HTTP DPoP semantics on the hosted edge
- Add continuation assertions for session reuse
- Bind session reuse to sender key continuity

### Milestone 5: Kernel subject-binding refactor

- Replace caller-supplied `agent_id` trust with verified caller context
- Bind `cap.subject` to authenticated sender key
- Remove or downgrade legacy paths

### Milestone 6: Stable identity continuity

- Derive or persist stable ARC subject from enterprise subject binding
- Gate strong identity claims on deterministic identity mode
- Add identity continuity tests and docs

### Milestone 7: Claim restoration

- Re-run adversarial validation
- Update README/spec/docs/discovery metadata
- Re-enable strong stolen-capability and PoP wording only for strict mode

## Acceptance Criteria

The hole is closed only when all of the following are true:

- No remotely authenticated strict-mode session can be resumed with changed scopes, changed enterprise claims, changed sender key, or changed token family without rejection.
- No strict-mode capability can be exercised without verified sender proof bound to the capability subject.
- Replay attempts are rejected across restart and across nodes for the full freshness window.
- Hosted-edge HTTP DPoP behavior matches the spec exactly, including claim fields and replay semantics.
- Kernel subject binding depends on verified caller context, not a caller-supplied string.
- Stable ARC agent identity for enterprise-authenticated sessions is deterministic or persisted, and the behavior is tested.
- README/spec/docs never make strong sender-constraint claims for compatibility or anonymous modes.
- A same-principal privilege-shrink regression test exists and passes.

## Risks/Non-Goals

### Risks

- Strict sender-constrained mode will break existing clients that only support bearer tokens or legacy ARC-native invocation without proof.
- Durable replay state adds operational complexity and may require a stronger shared store than the current HA control plane provides.
- Deterministic identity derivation can create correlation/privacy tradeoffs if the derivation scope is too broad.
- Enforcing exact-match session reuse may reduce UX for token refresh unless continuation assertions are implemented carefully.

### Non-Goals

- This remediation does not make anonymous or static-bearer mode equivalent to strict sender-constrained mode.
- This remediation does not solve all upstream IdP truthfulness issues; it only ensures ARC does not silently widen authority when claims drift.
- This remediation does not by itself solve cross-session process-state bleed in shared upstream runtimes, although strict mode should disable or constrain those deployments.
- This remediation does not require ARC-native invocation DPoP to look identical to OAuth DPoP, but it does require the spec to distinguish them precisely.
