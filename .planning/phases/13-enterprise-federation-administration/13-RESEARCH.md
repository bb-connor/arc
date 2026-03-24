# Phase 13: Enterprise Federation Administration - Research

**Researched:** 2026-03-24
**Domain:** Rust enterprise identity federation, provider-admin configuration, trust-control policy origin matching, operator diagnostics
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- Enterprise identity sources are named provider records with explicit type (`oidc_jwks`, `oauth_introspection`, `scim`, `saml`) plus tenant/org scoping, status, and provenance metadata.
- Provider onboarding is fail-closed; a provider cannot participate in portable-trust admission until required metadata, trust anchors, and subject-mapping inputs validate successfully.
- Provider-specific mapping remains explicit and reviewable; current Generic/Auth0/Okta/Azure AD heuristics may seed defaults but must not remain hidden one-off flag behavior.
- JWT, introspection, SCIM, and SAML inputs normalize into one canonical enterprise-origin envelope that preserves provider, tenant, organization, object/client identifiers, roles, groups, and raw subject identifiers.
- Stable PACT subject derivation must key off provider-scoped canonical principal identifiers, not mutable display data.
- Trust-control policy narrows admission with explicit provider/tenant/organization/role/group matches and must never widen trust silently.
- Admin and operator surfaces must show provider, federation method, normalized principal, derived subject key, and the exact enterprise context used for allow/deny decisions.

### Claude's Discretion

- Exact storage representation for provider records and sync metadata.
- Exact CLI command and HTTP route naming for provider-admin surfaces.
- Whether the first operator surface lands primarily in CLI, trust-control HTTP admin APIs, or both.

### Deferred Ideas (OUT OF SCOPE)

- Automatic SCIM provisioning and broader identity lifecycle management.
- Reusable signed verifier-policy artifacts and replay-state distribution (Phase 14).
- Multi-issuer passport semantics (Phase 15).
- Shared remote evidence analytics beyond identity provenance needed for Phase 13 admission/debugging (Phase 16).

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| FED-01 | Operator can onboard enterprise identity sources through provider-admin surfaces that cover SCIM and SAML-backed federation inputs rather than only raw bearer verifier settings | Provider record model, admin API/CLI surface, fail-closed validation path, docs, and onboarding diagnostics identified below |
| FED-02 | Trust-control policy can allow or deny portable-trust admission using provider, tenant, organization, role, and group context without silently widening trust | Existing policy origin model is identified, gaps are explicit, and recommended extension path preserves fail-closed evaluation and operator-visible provenance |

</phase_requirements>

---

## Summary

Phase 13 should be implemented as an extension of the shipped federation alpha, not a parallel subsystem. The core seam already exists: `crates/pact-cli/src/remote_mcp.rs` authenticates bearer requests, derives stable principal strings, normalizes tenant/org/group/role data into `OAuthBearerFederatedClaims`, and exposes that context through `SessionAuthContext`. The missing work is turning that bearer-only alpha into an administrable enterprise federation surface with explicit provider records, SCIM/SAML normalization, portable-trust admission gating, and operator diagnostics.

The most important architectural recommendation is to introduce a transport-agnostic enterprise identity context instead of stretching `OAuthBearerFederatedClaims` to cover every new source. `OAuthBearerFederatedClaims` is already bearer-specific by name and shape inside `pact-core/src/session.rs`; forcing SCIM and SAML through it would leak transport assumptions into future phases. Bearer JWT/introspection inputs should convert into the broader enterprise identity context, and SCIM/SAML normalization should produce the same structure directly.

The policy side already has a natural home for this work. `pact-policy` exposes `OriginContext`, `OriginMatch`, and origin-profile scoring today, but the model only has `provider`, `tenant_id`, and a single `actor_role`. Phase 13 should extend that existing origin-matching path with `organization_id`, repeated `groups`, and repeated `roles` rather than hiding enterprise identity in generic tags or inventing a second policy engine. That keeps portable-trust admission on one truthful policy path and makes allow/deny explanations reusable across CLI, HTTP, and tests.

**Primary recommendation:** land Phase 13 in four slices that mirror the roadmap plans: provider-admin model and persistence in `pact-cli`; transport-agnostic enterprise identity normalization in `pact-core` plus source-specific adapters in `pact-cli`; policy origin-model expansion in `pact-policy`; then admin/reporting/test/doc wiring in `pact-cli/tests`, guides, and changelog. Keep bearer federation backward-compatible by treating JWT/introspection as provider kinds inside the broader provider-admin model.

---

## Existing Baseline

### What already exists

- `crates/pact-cli/src/remote_mcp.rs`
  - verifies JWTs and introspected opaque tokens
  - supports provider-profile principal mapping for Generic/Auth0/Okta/Azure AD
  - derives stable subject keys from normalized principals
  - preserves `tenant_id`, `organization_id`, `groups`, and `roles`
  - already has direct tests for normalized federated claims and stable subject derivation
- `crates/pact-core/src/session.rs`
  - serializes normalized bearer auth context into `SessionAuthContext`
  - carries `OAuthBearerFederatedClaims` with `client_id`, `object_id`, `tenant_id`, `organization_id`, `groups`, and `roles`
- `crates/pact-policy/src/models.rs` and `crates/pact-policy/src/evaluate.rs`
  - already provide a policy origin model and origin-profile selection logic
  - can match `provider` and `tenant_id` today
  - do not yet represent organization, group lists, or multiple roles cleanly
- `crates/pact-cli/src/trust_control.rs`
  - already hosts portable-trust issuance and operator/debugging HTTP surfaces
  - is the natural place to enforce provenance-aware portable-trust admission and expose federation diagnostics
- `crates/pact-cli/tests/mcp_serve_http.rs`
  - already verifies `authContext.method.federatedClaims` values over the real HTTP/admin surface
  - should be reused for enterprise-provider regression coverage

### What is missing

- No durable provider-admin model; current federation configuration is still mostly raw `serve-http` flags.
- No SCIM or SAML-backed normalization path.
- No transport-agnostic enterprise identity context shared across sources.
- No portable-trust policy path that can match organization, groups, or multiple roles directly.
- No provider-admin/operator reporting surface that explains enterprise provenance end-to-end for portable-trust admission.

---

## Standard Stack

### Core

| Library | Purpose | Recommendation |
|---------|---------|----------------|
| Existing Rust workspace types (`serde`, `serde_json`, `url`, `reqwest`, `thiserror`, `tracing`) | Provider config, metadata fetch, normalization, fail-closed diagnostics | Reuse existing workspace stack; no new dependency is needed for provider-admin, JWT/introspection extension, or policy expansion |
| Existing HTTP/admin surfaces in `axum` | Provider-admin and operator diagnostics endpoints | Reuse current `pact-cli` service surface rather than creating a separate admin service |

### Conditional

| Library | Purpose | When to Use |
|---------|---------|-------------|
| `quick-xml` or equivalent XML parser | SAML metadata/assertion parsing | Only add if Phase 13 implements real XML parsing; do not add preemptively if the first cut normalizes validated fixture/assertion payloads through explicit structs |

### Recommendation

The research supports a conservative dependency posture: Phase 13 can make real progress without adding any new library except a dedicated XML parser if SAML assertion parsing becomes unavoidable in this milestone. SCIM data is JSON-native and fits the existing workspace stack directly.

---

## Architecture Patterns

### Recommended Project Structure

```text
crates/pact-core/src/
├── session.rs                    # existing auth context types; may gain transport-agnostic enterprise identity type
└── [new shared identity module]  # if needed for source-agnostic enterprise identity structs

crates/pact-policy/src/
├── models.rs                     # extend origin matching schema
├── evaluate.rs                   # extend origin matching + allow/deny reporting
└── receipt.rs                    # ensure evaluation output stays provenance-visible

crates/pact-cli/src/
├── remote_mcp.rs                 # current bearer federation; refactor to reuse shared enterprise identity normalization
├── trust_control.rs              # provider-admin APIs, portable-trust gating, diagnostics/reporting
├── policy.rs                     # bridge normalized enterprise identity into portable-trust policy evaluation
└── [new federation admin module] # provider records, validation, SCIM/SAML normalization helpers if extraction is warranted

crates/pact-cli/tests/
├── mcp_serve_http.rs             # extend bearer/admin trust assertions
├── federated_issue.rs            # extend portable-trust issuance gating coverage
└── [new federation admin tests]  # provider-admin + SCIM/SAML normalization integration tests
```

### Pattern 1: Provider Record as Durable Source of Truth

**What:** Replace ad hoc provider flags as the long-term source of truth with a provider-admin record that captures provider kind, issuer/entity identifiers, tenant/org scope, trust material, mapping hints, status, and provenance.

**Why:** Current raw `serve-http` flags are enough for bearer alpha, but they do not support auditable enterprise onboarding or portable-trust debugging. A provider record gives one place to explain what was configured and why a request was accepted or denied.

**Recommendation:**
- Keep JWT and introspection as provider kinds inside this model so existing deployments can migrate without semantic drift.
- Separate validation state from enablement state: invalid or incomplete provider records exist for diagnostics, but they cannot be used for admission.
- Persist mapping hints explicitly; do not rely on hidden provider-profile heuristics once a provider is onboarded.

### Pattern 2: Transport-Agnostic Enterprise Identity Context

**What:** Introduce a shared normalized identity structure that can be produced from bearer JWT/introspection, SCIM, and SAML without tying the downstream policy path to one transport.

**Why:** `OAuthBearerFederatedClaims` already proves the fields PACT needs, but the name and location make it a poor long-term home for SCIM/SAML. Phase 13 needs one canonical context for subject derivation, policy evaluation, and diagnostics.

**Recommendation:**
- Bearer flows convert existing normalized claims into the broader enterprise identity context.
- SCIM and SAML normalization produce the same context directly.
- The context should include:
  - provider identifier
  - federation method
  - canonical principal string used for subject derivation
  - client/object identifiers when present
  - tenant and organization identifiers
  - normalized groups and roles
  - source-native provenance fields for debugging
- Preserve raw source material only where needed for diagnostics; portable-trust policy should evaluate normalized fields.

### Pattern 3: Extend Existing Origin Matching, Do Not Fork Policy

**What:** Reuse `pact-policy`'s `OriginContext` / `OriginMatch` path rather than creating a separate enterprise-policy evaluator.

**Why:** `pact-policy` already does fail-closed origin-profile selection, which is the closest existing contract to enterprise-provider admission. Forking policy logic here would make allow/deny explanations diverge.

**Recommendation:**
- Extend the origin model with:
  - `organization_id`
  - repeated `groups`
  - repeated `roles`
  - possibly a clearer provider/source identifier if current `provider` is too coarse
- Do not overload `tags` for group membership and do not collapse multi-role input into the existing single `actor_role` field.
- Preserve deny reasons that explain exactly which field did not match.
- Ensure absence of optional fields never widens trust. If a rule depends on `organization_id`, `groups`, or `roles`, missing data must deny.

### Pattern 4: Portable-Trust Admission Must Reuse Enterprise Provenance

**What:** The provider-admin lane must feed into portable-trust issuance and verification surfaces, not stop at remote MCP session auth.

**Why:** FED-02 is specifically about portable-trust admission. The current alpha captures enterprise claims in auth/admin surfaces, but the policy gate for federated issue still needs to consume that context truthfully.

**Recommendation:**
- `trust_control.rs` should retain the normalized enterprise context that participated in allow/deny decisions.
- Federated issue responses and diagnostics should expose which provider record and which policy clause decided the request.
- Keep this provenance visible through both CLI and HTTP operator surfaces.

### Pattern 5: Diagnostics Over Wizardry

**What:** Make the first operator surface table-first and evidence-first.

**Why:** The codebase already favors explicit admin/read-model outputs over heavy UI abstraction. Phase 13 needs operator trust more than polished onboarding UX.

**Recommendation:**
- Start with CLI plus JSON/HTTP admin APIs if needed; those can later back richer UI.
- Expose:
  - provider status and validation failures
  - normalized principal and derived subject key
  - normalized tenant/org/group/role values
  - source method and source identifiers
  - policy decision and matched clause

---

## Key Risks and Pitfalls

### Risk 1: Reusing bearer-specific types for SCIM/SAML

**Why it matters:** This would lock Phase 13 into transport-specific naming and make later identity sources harder to reason about.

**Mitigation:** Introduce a transport-agnostic identity type in `pact-core` and convert bearer claims into it.

### Risk 2: Hiding enterprise identity inside generic policy tags

**Why it matters:** Tags are too lossy for fail-closed authorization and make deny explanations weak.

**Mitigation:** Add first-class policy fields for organization, groups, and roles.

### Risk 3: Provider-admin model bypassed by legacy raw flags

**Why it matters:** Portable-trust admission could silently diverge between “legacy” and “enterprise” paths.

**Mitigation:** Keep backward compatibility by treating JWT/introspection as provider kinds inside the new model and routing enterprise admission through one canonical config/evaluation path.

### Risk 4: Trust widening through partial normalization

**Why it matters:** Missing tenant/org/role/group values are exactly where enterprise auth bugs become authorization bugs.

**Mitigation:** Normalize fail-closed and deny when required fields or mappings are ambiguous.

### Risk 5: Diagnostics drift between CLI, HTTP, and tests

**Why it matters:** Operators need one explanation path, and the project already expects CLI and HTTP surfaces to agree.

**Mitigation:** Reuse shared response types and extend existing integration tests rather than duplicating formatter logic in multiple places.

---

## Testing Strategy

### Existing infrastructure to reuse

- `cargo test -p pact-cli mcp_serve_http`
  - already exercises remote bearer admission and admin trust surfaces
- `cargo test -p pact-cli federated_issue`
  - already exercises portable-trust issuance surfaces
- `cargo test -p pact-policy`
  - already validates origin matching logic

### High-value new tests

- Provider-admin validation rejects incomplete or conflicting provider records.
- SCIM identity payload normalizes to the same canonical enterprise context fields used by bearer federation.
- SAML identity payload/assertion normalizes to the same canonical enterprise context fields and fails closed on ambiguous subject mapping.
- Policy origin matching denies when organization/group/role requirements are missing or mismatched.
- Portable-trust federated admission explainably allows/denies based on provider, tenant, organization, groups, and roles.
- CLI and HTTP diagnostics expose the same enterprise provenance for the same scenario.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (`cargo test`) |
| Config file | none -- inline `#[test]` and `#[tokio::test]` plus existing integration-test crates |
| Quick run command | `cargo test -p pact-cli --test mcp_serve_http --test federated_issue && cargo test -p pact-policy` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FED-01 | Provider-admin surface persists explicit provider records with validation and status reporting | integration | `cargo test -p pact-cli provider_admin` | No -- Wave 0 |
| FED-01 | SCIM-backed identity payloads normalize into stable principal and subject derivation inputs | unit/integration | `cargo test -p pact-cli scim_identity` | No -- Wave 0 |
| FED-01 | SAML-backed identity payloads/assertions normalize or fail closed on ambiguous mappings | unit/integration | `cargo test -p pact-cli saml_identity` | No -- Wave 0 |
| FED-02 | Policy origin matching supports provider, tenant, organization, groups, and roles without fallback widening | unit | `cargo test -p pact-policy enterprise_origin` | No -- Wave 0 |
| FED-02 | Portable-trust admission explainably allows/denies based on enterprise identity context | integration | `cargo test -p pact-cli federated_issue enterprise_admission` | Partially -- extend existing |
| FED-02 | Admin/operator diagnostics show normalized provenance consistently across HTTP and CLI | integration | `cargo test -p pact-cli mcp_serve_http enterprise_diagnostics` | Partially -- extend existing |

### Sampling Rate

- **Per task commit:** run the smallest relevant crate/test target for the files touched (`pact-policy`, `mcp_serve_http`, `federated_issue`, or new provider-admin tests)
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** full workspace tests green before verification closeout

### Wave 0 Gaps

- [ ] Shared enterprise identity type or module in `pact-core` if Phase 13 extracts transport-agnostic normalization
- [ ] Provider-admin record types and validation path in `pact-cli`
- [ ] SCIM normalization fixtures/tests
- [ ] SAML normalization fixtures/tests
- [ ] Policy schema/evaluator coverage for organization, groups, and roles
- [ ] Portable-trust admission provenance assertions in `federated_issue` coverage

---

## Sources

### Primary (HIGH confidence)

- `.planning/phases/13-enterprise-federation-administration/13-CONTEXT.md` -- locked decisions and deferred scope
- `.planning/ROADMAP.md` -- Phase 13 goal, success criteria, and plan split
- `.planning/REQUIREMENTS.md` -- `FED-01` and `FED-02`
- `CLAUDE.md` -- project conventions and release gates
- `docs/IDENTITY_FEDERATION_GUIDE.md` -- shipped federation alpha boundary
- `docs/AGENT_PASSPORT_GUIDE.md` -- current portable-trust and federated issue surfaces
- `crates/pact-cli/src/remote_mcp.rs` -- normalized bearer federation, stable principal derivation, admin trust surfaces, and existing tests
- `crates/pact-core/src/session.rs` -- `SessionAuthContext` and `OAuthBearerFederatedClaims`
- `crates/pact-policy/src/models.rs` and `crates/pact-policy/src/evaluate.rs` -- origin model and fail-closed matching logic
- `crates/pact-cli/src/trust_control.rs` -- portable-trust admission and operator surface entrypoints
- `crates/pact-cli/tests/mcp_serve_http.rs` -- current end-to-end enterprise-claim/admin-surface coverage

### Secondary (MEDIUM confidence)

- `docs/CHANGELOG.md` -- exact shipped boundary for OIDC discovery, introspection, portable verifier policy, and federated issue
- `docs/STRATEGIC_ROADMAP.md` and `docs/VISION.md` -- milestone positioning and product intent

---

## Metadata

**Confidence breakdown:**
- Existing code seams: HIGH -- verified directly in source and tests
- Recommended architecture: HIGH -- follows already shipped bearer/admin/policy boundaries
- Dependency posture: MEDIUM -- no new library appears necessary except a possible XML parser if real SAML parsing is implemented in this phase
- Validation strategy: HIGH -- directly aligned with existing Rust workspace test structure

**Research date:** 2026-03-24
**Valid until:** 2026-05-24
