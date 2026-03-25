# Phase 14: Portable Verifier Distribution and Replay Safety - Context

**Gathered:** 2026-03-24
**Status:** Completed

<domain>
## Phase Boundary

Phase 14 turns the shipped passport verifier alpha into a reusable verifier
infrastructure surface. Verifier policies become signed artifacts that can be
stored and referenced by ID, challenge replay state becomes persistent and
consumable across process restarts, and local plus remote verifier flows expose
the same explicit policy and replay semantics. This phase does not define
multi-issuer passport composition, cluster-wide replay-state replication, or
shared remote evidence analytics.

</domain>

<decisions>
## Implementation Decisions

### Verifier Policy Artifact Model
- Reusable verifier policy is modeled as a signed artifact, not an unsigned
  inline blob. The signed body binds `policy_id`, `verifier`, validity window,
  signer public key, and the underlying `PassportVerifierPolicy`.
- Stored verifier policies live in a versioned JSON registry
  (`pact.passport-verifier-policies.v1`) so local CLI and trust-control can use
  the same durable source of truth.
- A challenge may carry either an embedded policy or a `policyRef`, but never
  both at once.
- A stored policy reference is only valid when the resolved policy's
  `verifier` matches the challenge verifier exactly.

### Replay-Safe Challenge State
- Replay safety is enforced by a durable SQLite challenge store instead of
  exact in-memory challenge matching only.
- Each stored challenge is bound to a canonical hash of the full challenge
  payload so a challenge ID cannot be reused with mutated policy or verifier
  fields.
- Challenge state is explicit: `issued`, `consumed`, and `expired`.
- Consumption happens on verifier-side success paths, including remote
  `trust federated-issue`, so the same challenge cannot be replayed after a
  process restart.

### Local and Remote Parity
- Local CLI and trust-control surfaces share one truth model:
  `challengeId`, `policyId`, `policySource`, `policyEvaluated`, and
  `replayState`.
- Local file-backed flows use `--verifier-policies-file` and
  `--verifier-challenge-db`.
- Remote flows use the same semantics through `--control-url` and
  `--control-token`, backed by trust-control verifier-policy and challenge
  endpoints.
- Remote stored-policy references fail closed unless the trust-control service
  is configured with both a verifier policy registry and a replay-state
  database.

### Operator Reporting
- Verification output must distinguish structural passport validity from policy
  acceptance.
- Verifier surfaces must explain where policy came from (`embedded` vs
  `registry:<id>`) and whether replay-safe state was consumed.
- Admin operators need CRUD visibility for verifier policies, not only implicit
  challenge creation behavior.

### Claude's Discretion
- Exact storage format for the verifier policy registry as long as it remains
  versioned, signed, and operator-visible.
- Exact SQLite schema for replay-safe challenge state as long as it binds the
  stored row to the exact challenge payload and enforces one-time consumption.
- Exact CLI route naming as long as it stays consistent with the existing
  `pact passport` and `pact trust serve` surfaces.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 14 goal, plans, and success criteria
- `.planning/REQUIREMENTS.md` -- `VER-01`, `VER-02`, `VER-03`
- `.planning/STATE.md` -- current milestone position and downstream phase split
- `docs/AGENT_PASSPORT_GUIDE.md` -- shipped passport and verifier workflow docs
- `docs/CHANGELOG.md` -- milestone-level verifier infrastructure changelog
- `.planning/phases/13-enterprise-federation-administration/13-VERIFICATION.md`
  -- prior phase output that this phase extends

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/pact-credentials/src/lib.rs` -- canonical passport, challenge,
  evaluation, and signed-artifact types
- `crates/pact-cli/src/passport_verifier.rs` -- registry and replay-store
  helpers added for this phase
- `crates/pact-cli/src/passport.rs` -- local/remote CLI flows for policy and
  challenge handling
- `crates/pact-cli/src/trust_control.rs` -- trust-control verifier policy CRUD,
  challenge create/verify, and federated-issue integration
- `crates/pact-cli/tests/passport.rs` -- local replay-safe policy-reference
  coverage
- `crates/pact-cli/tests/federated_issue.rs` -- remote replay-safe verifier
  challenge coverage
- `crates/pact-cli/tests/provider_admin.rs` -- remote verifier policy admin CRUD

### Established Patterns
- Signed artifacts in PACT bind schema, signer key, validity window, and the
  protected body under canonical JSON verification.
- Local and remote operator surfaces in `pact-cli` usually share Rust types,
  JSON shape, and integration coverage.
- Security-sensitive verifier behavior fails closed when required storage or
  bound verifier identity is missing.

### Integration Points
- `passport challenge create` now needs to compose with reusable verifier
  policy references instead of only embedded inline policy.
- `passport challenge verify` and `trust federated-issue` both need one-time
  consumption of the same durable challenge state.
- `reputation compare` and local verifier policy loading must accept signed
  verifier policy documents in addition to raw policy files.

</code_context>

<specifics>
## Specific Ideas

- Keep challenge references simple: `policyRef.policyId` is enough because the
  verifier registry is already verifier-bound and signature-checked.
- Reuse the same signed verifier artifact for local file-backed flows and
  remote trust-control CRUD so docs do not have to explain separate policy
  formats.
- Make replay safety visible in output; hidden state transitions are too hard
  to debug operationally.

</specifics>

<deferred>
## Deferred Ideas

- Multi-issuer passport composition and issuer-aware aggregate reporting
  (Phase 15)
- Cluster-wide replication or quorum semantics for verifier challenge state
- Shared remote evidence references and cross-org analytics/reporting
  (Phase 16)

</deferred>

---

*Phase: 14-portable-verifier-distribution-and-replay-safety*
*Context gathered: 2026-03-24*
