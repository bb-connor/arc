# Phase 13: Enterprise Federation Administration - Context

**Gathered:** 2026-03-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 13 turns the shipped bearer-authenticated identity-federation alpha into an administrable enterprise federation surface. It adds provider-admin configuration, SCIM/SAML-backed identity normalization, policy-visible enterprise identity context, and operator debugging/provenance for portable-trust admission. It does not define reusable verifier artifacts, multi-issuer passport semantics, or broader cross-org analytics beyond the identity provenance needed for truthful admission and debugging.

</domain>

<decisions>
## Implementation Decisions

### Provider Administration Surface
- Enterprise identity sources are modeled as named provider records with explicit type (`oidc_jwks`, `oauth_introspection`, `scim`, `saml`) plus tenant/org scoping, status, and provenance metadata rather than loose per-flag bearer settings.
- Provider onboarding stays fail-closed: a provider cannot participate in portable-trust admission until required metadata, trust anchors, and subject-mapping inputs validate successfully.
- Provider-specific mapping remains explicit and reviewable; shipped Generic/Auth0/Okta/Azure AD heuristics can seed defaults, but the admin surface must persist the resolved mapping and trust boundaries instead of hiding them in one-off flags.
- Operator/admin output should prioritize auditable tables and JSON/CLI parity over wizard-style UX; the first cut is an operator-grade configuration and diagnostics surface, not a self-serve identity portal.

### Enterprise Identity Normalization
- JWT, introspection, SCIM, and SAML inputs must normalize into one canonical enterprise-origin envelope that preserves provider, tenant, organization, object/client identifiers, roles, groups, and raw subject identifiers.
- Stable PACT subject derivation must be keyed from provider-scoped canonical principal identifiers, not mutable display attributes such as email or display name.
- Groups and roles are preserved as normalized lists plus provider-native provenance so policy/debugging can explain exactly which source attribute produced each value.
- Ambiguous or partial mappings deny admission; PACT must not silently drop unresolved tenant/org/role/group context and continue with widened trust.

### Policy Admission Semantics
- Trust-control policy rules for enterprise federation are allow-by-explicit-match and only narrow admission; missing provider, tenant, organization, role, or group constraints never widen an otherwise stricter decision.
- Policy evaluation must distinguish issuer/provider identity from subject membership attributes so a token or assertion cannot satisfy both by accident through fallback matching.
- Portable-trust admission decisions must retain the normalized federation context that was evaluated, including which provider record and which policy clause allowed or denied the request.
- Existing bearer federation flows remain supported, but once a request enters the enterprise-provider lane it must use the provider-admin config and enterprise policy path rather than bypassing them with ad hoc raw flags.

### Operator Provenance and Diagnostics
- Admin and trust-control surfaces should show the source provider, federation method (`jwt`, `introspection`, `scim`, `saml`), normalized principal, derived subject key, and the tenant/org/role/group context used for admission.
- Deny and parse-failure responses should explain which required field, policy clause, or trust anchor check failed without exposing secrets or raw credentials.
- CLI and HTTP diagnostics should share one truth model so operator debugging matches what automated tests and remote clients observe.
- End-to-end coverage should use realistic provider fixtures (Generic/Auth0/Okta/Azure AD plus SCIM/SAML samples) to prove no trust widening across mixed enterprise inputs.

### Claude's Discretion
- Exact storage shape for provider records and sync metadata as long as it preserves auditable provenance and fail-closed validation.
- Exact CLI command names and HTTP route naming for the admin surface as long as they stay consistent with existing `pact trust` and `pact mcp serve-http` conventions.
- Whether the first operator surface lands primarily in CLI, trust-control HTTP admin APIs, or both in the first wave, provided docs and tests cover the shipped path.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope and acceptance
- `.planning/ROADMAP.md` — Phase 13 goal, success criteria, and plan breakdown for enterprise federation administration.
- `.planning/REQUIREMENTS.md` — `FED-01` and `FED-02` traceability plus fail-closed scope for provider-admin and policy-visible identity context.
- `.planning/STATE.md` — Current milestone decisions, especially that bearer federation alpha exists and multi-issuer semantics remain out of scope.

### Shipped federation baseline
- `docs/IDENTITY_FEDERATION_GUIDE.md` — Current JWT/OIDC/introspection federation behavior, normalized claims, and explicit non-goals (`SCIM`, `SAML`, provider-admin still missing).
- `docs/CHANGELOG.md` — Shipped OIDC discovery, introspection, passport verifier, and federated issuance boundary that Phase 13 extends.
- `docs/STRATEGIC_ROADMAP.md` — Identity federation and cross-org delegation positioning; confirms the remaining work is richer identity/admin integration rather than first multi-hop reconstruction.

### Portable-trust dependence
- `docs/AGENT_PASSPORT_GUIDE.md` — Current passport evaluation, challenge, and federated issuance flow that enterprise identity policy must gate truthfully.
- `docs/VISION.md` — Product intent for portable trust, cross-org identity, and operator-visible provenance.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/pact-cli/src/remote_mcp.rs` — Current JWT/OIDC/introspection admission, federated-claim normalization, and stable subject derivation helpers that Phase 13 should extend rather than replace.
- `crates/pact-core/src/session.rs` — `OAuthBearerFederatedClaims` and session auth-context types already carry provider, tenant, organization, group, and role data into admin surfaces.
- `crates/pact-policy/src/models.rs` and `crates/pact-policy/src/evaluate.rs` — Origin policy structs already have provider/tenant/role-style fields and are the natural home for enterprise admission constraints.
- `crates/pact-cli/src/trust_control.rs` — Federated issuance endpoint plus operator HTTP/reporting surfaces where provider-admin and provenance-aware admission/debugging must land.
- `crates/pact-cli/src/main.rs` — Existing `pact mcp serve-http` auth flags and `pact trust` command organization define the operator-facing entrypoint conventions.

### Established Patterns
- Security-sensitive inputs fail closed on ambiguous issuer metadata, incompatible keys, inactive tokens, or malformed claims; enterprise federation should extend that posture to SCIM/SAML inputs and provider-admin configuration.
- Operator surfaces in PACT usually ship with both CLI and HTTP trust-control coverage backed by the same underlying Rust types and integration tests.
- Existing identity federation logic keeps provider-specific mapping explicit (`JwtProviderProfile`) and preserves normalized enterprise claims in auth context instead of re-parsing raw tokens later.
- New functionality typically lands with guide/changelog updates plus crate integration tests rather than hidden wiring.

### Integration Points
- Remote bearer admission and provider metadata bootstrap live in `crates/pact-cli/src/remote_mcp.rs`; provider-admin config likely feeds this boundary.
- Portable-trust issuance and operator debugging live in `crates/pact-cli/src/trust_control.rs`, which is where admission outcomes and provenance need to stay visible.
- Policy schema/evaluator extensions in `crates/pact-policy` must line up with how normalized federation context is captured in `crates/pact-core/src/session.rs`.
- CLI flag and command changes need to remain compatible with existing `pact mcp serve-http`, `pact trust federated-issue`, and admin API conventions.

</code_context>

<specifics>
## Specific Ideas

- Use enterprise-provider records as the durable source of truth instead of growing more one-off `serve-http` auth flags.
- Keep bearer JWT and introspection as provider kinds within the broader admin model so current deployments can migrate without semantic drift.
- Treat SCIM and SAML as identity-context producers first; full provisioning or broader lifecycle management is not required for this phase.
- Admission and debugging output should make it obvious which provider, tenant, organization, role, and group values were actually used to derive the subject and evaluate policy.

</specifics>

<deferred>
## Deferred Ideas

- Automatic SCIM provisioning workflows and broader identity lifecycle management beyond normalized admission context.
- Reusable signed verifier-policy artifacts and replay-state distribution; that belongs to Phase 14.
- Multi-issuer portable credential semantics; that belongs to Phase 15.
- Cross-org remote evidence analytics and dashboard drift/reporting expansions beyond the identity provenance needed for Phase 13 admission and debugging.

</deferred>

---

*Phase: 13-enterprise-federation-administration*
*Context gathered: 2026-03-24*
