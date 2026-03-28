# Phase 53: OID4VCI-Compatible Issuance and Delivery - Research

**Researched:** 2026-03-27
**Domain:** OID4VCI issuance over ARC Agent Passport artifacts
**Confidence:** MEDIUM

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

### Issuance scope
- Ship one conservative OID4VCI-style issuance lane rather than a broad wallet
  ecosystem abstraction.
- Treat interoperability as an external delivery and issuance contract layered
  over existing ARC passport artifacts, not as a rewrite of ARC's credential
  cryptography or identity model.
- Keep the scope operator-bounded and explicitly non-public; no global issuer
  discovery or wallet marketplace semantics are introduced in this phase.

### Credential model and trust boundaries
- Preserve the current ARC-native credential and passport substrate:
  `did:arc` issuer and subject identifiers, Ed25519-signed credentials, and
  ARC passport bundle semantics remain the source of truth.
- Expose interoperable issuance as a profile mapping from ARC passport
  artifacts into an OID4VCI-compatible offer and retrieval flow.
- Fail closed when requested formats, profile identifiers, issuance metadata,
  audience, or subject binding do not match the configured issuer contract.

### Delivery surfaces
- Support both local CLI and trust-control delivery surfaces so operators can
  test flows locally and expose them remotely through the existing admin plane.
- Use replay-safe issuance grants or offer codes instead of anonymous raw file
  download links.
- Keep issuance state explicit and inspectable rather than hiding it inside
  transient process memory.

### Claude's Discretion
- Exact naming of the interoperable offer and metadata document types.
- Whether the first delivery artifact wraps full passports, individual
  credentials, or both, as long as the scope stays within the phase boundary.
- Whether one-time offer state lives in SQLite or a file-backed registry, as
  long as it is durable enough for operator and test flows.

### Deferred Ideas (OUT OF SCOPE)
- Portable status, revocation, and supersession distribution contracts —
  phase 54
- Holder-facing wallet transport and presentation semantics — phase 55
- External verifier or wallet compatibility proof and qualification — phase 56
- Any public marketplace, global issuer registry, or automatic authority
  widening semantics
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| VC-01 | ARC supports at least one interoperable credential-issuance flow aligned with external VC ecosystem expectations rather than only ARC-native file and API delivery. | Use one issuer-initiated OID4VCI 1.0 pre-authorized-code flow with a custom ARC credential format profile that delivers an existing ARC passport artifact through standard offer, token, and credential endpoints. |
| VC-05 | Broader credential interop preserves ARC's conservative rules against synthetic global trust, silent federation, and authority widening. | Keep `did:arc` and ARC passport truth unchanged, use no public discovery, require exact `credential_issuer` to `did:arc` binding, default to short-lived single-use offers, and reject unsupported formats or subject mismatches fail closed. |
</phase_requirements>

## Summary

ARC should implement Phase 53 as a narrow OID4VCI 1.0 issuer-initiated,
pre-authorized-code flow that delivers one existing ARC artifact type, not as
a conversion of ARC into a generic VC issuer. The most conservative first
artifact is the full `AgentPassport`, because ARC's current verifier policy,
challenge, lifecycle, and docs all treat the passport bundle as the portable
truth surface rather than any one embedded credential.

The central compatibility constraint is that ARC's current credential proof
semantics are not a standard OpenID4VCI `ldp_vc` profile. ARC signs credential
bodies with RFC 8785 canonical JSON and labels proofs as
`Ed25519Signature2020`, while OpenID4VCI's `ldp_vc` profile is specifically for
W3C Data Integrity with JSON-LD and a proof suite that uses linked-data
canonicalization. That means Phase 53 should use OID4VCI's extension points to
define an ARC-specific credential format profile instead of mislabeling ARC
passports as generic `ldp_vc`, `jwt_vc_json`, or `dc+sd-jwt`.

Remote issuance should be exposed through existing trust-control deployment
patterns, using `--advertise-url` as the external `credential_issuer` base and
assuming TLS terminates at an operator-controlled HTTPS edge or reverse proxy.
Local CLI flows should reuse the same typed offer and redemption contracts for
operator testing, but docs must be explicit that standards-facing remote
compatibility depends on an HTTPS-advertised base URL.

**Primary recommendation:** Ship one `ArcAgentPassportV1` OID4VCI
pre-authorized-code flow over existing ARC passports, backed by a SQLite
single-use offer store, fronted by an HTTPS `advertise_url`, and do not claim
standard `ldp_vc`, SD-JWT VC, or wallet qualification yet.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `arc-credentials` | `0.1.0` workspace | Source-of-truth passport, credential, policy, and validation types | Phase 53 must map from existing ARC artifacts, not replace them. |
| `arc-cli` | `0.1.0` workspace | Local operator commands, trust-control routes, and remote client support | Existing CLI and trust-control surfaces are the required delivery planes. |
| `axum` | workspace pin `0.8` (`0.8.8` latest verified 2026-03-27) | Wallet-facing metadata, token, credential, and offer endpoints | Already powers trust-control HTTP routing; no new web stack is needed. |
| `serde` / `serde_json` | workspace pin `1` | Typed OID4VCI documents and exact fail-closed validation | ARC already models signed and transport contracts this way. |
| `rusqlite` | workspace pin `0.37` (`0.39.0` latest verified 2026-03-27) | Durable one-time offer, pre-auth code, and access-token state | Existing replay-safe challenge state already uses SQLite patterns. |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `serde_urlencoded` | `0.7` (`0.7.1` latest verified 2026-03-27) | `application/x-www-form-urlencoded` token requests | Required for spec-shaped token endpoint parsing. |
| `ureq` | workspace pin `2.10` (`3.3.0` latest verified 2026-03-27) | Existing blocking trust-control client | Reuse for CLI-to-trust-control OID4VCI admin paths. |
| `chrono` | `0.4` (`0.4.44` latest verified 2026-03-27) | RFC3339 and expiry handling | Consistent timestamp formatting across credential and offer documents. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Existing `axum` plus typed ARC contracts | A generic OID4VCI server library | Hides ARC-specific fail-closed mapping rules and adds dependency surface for only one conservative flow. |
| SQLite offer store | File-backed registry | Simpler operationally, but weaker for atomic single-use redemption and replay-safe state transitions. |
| Pre-authorized-code flow | Authorization-code plus PAR and DPoP | More interoperable for high-assurance ecosystems, but too large for Phase 53 and not aligned with the operator-mediated first slice. |

**Dependency posture:**

```bash
# No new external crates are required for the conservative first lane.
# Reuse the existing workspace pins already present in Cargo.toml.
```

**Version verification:** External crate versions above were checked on
2026-03-27 with `cargo search`. The recommendation is to keep current workspace
pins in Phase 53 and avoid version upgrades unless the phase is otherwise
blocked.

## Architecture Patterns

### Recommended Project Structure

```text
crates/
├── arc-credentials/
│   └── src/
│       └── oid4vci.rs              # typed ARC issuance profile, metadata, offer, token, request, response validation
├── arc-cli/
│   └── src/
│       ├── passport_issuance.rs    # local offer creation, local redemption helpers, store adapter
│       ├── passport.rs             # command wiring only
│       ├── passport_verifier.rs    # durable offer/pre-auth store or shared SQLite helpers
│       └── trust_control.rs        # route registration plus thin handler glue
└── arc-cli/tests/
    └── passport.rs                 # local and remote issuance regression
```

### Pattern 1: Profile Mapping, Not Credential Rewrite

**What:** Define an ARC-specific OID4VCI credential format profile whose
payload is an existing `AgentPassport` JSON artifact.

**When to use:** For the first interoperable issuance lane in Phase 53.

**Example:**

```json
{
  "credential_issuer": "https://trust.example.com",
  "credential_configurations_supported": {
    "ArcAgentPassportV1": {
      "format": "application/arc-passport+json",
      "scope": "arc_agent_passport_v1",
      "credential_metadata": {
        "display": [{ "name": "ARC Agent Passport" }]
      },
      "arc_profile": {
        "artifact_schema": "arc.agent-passport.v1",
        "issuer_id_method": "did:arc",
        "subject_id_method": "did:arc"
      }
    }
  }
}
```

Source: OpenID4VCI 1.0 Appendix A extension points allow deployment-specific
credential format profiles; the `arc_profile` object above is an ARC-specific
inference built on that extension mechanism.

### Pattern 2: One Offer, One Configuration, One Redemption

**What:** Persist a single credential configuration per offer and treat the
pre-authorized code as short-lived and single use.

**When to use:** For every Phase 53 issuance offer.

**Example:**

```json
{
  "credential_issuer": "https://trust.example.com",
  "credential_configuration_ids": ["ArcAgentPassportV1"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "opaque-single-use-code",
      "tx_code": {
        "length": 6,
        "input_mode": "numeric",
        "description": "Enter the one-time code sent out of band"
      }
    }
  }
}
```

Source: OpenID4VCI 1.0 sections 4.1.1 and 13.6 define `credential_issuer`,
`credential_configuration_ids`, `pre-authorized_code`, and optional `tx_code`.

### Pattern 3: Split Operator and Holder Trust Planes

**What:** Keep offer creation and lifecycle management behind ARC's existing
service-token admin plane, while exposing wallet-facing token and credential
endpoints that are bounded only by the offer state, pre-authorized code, and
short-lived access token.

**When to use:** For trust-control deployment.

**Example:**

```text
Operator-authenticated:
- POST /v1/passport/issuance/offers
- GET  /v1/passport/issuance/offers/{offer_id}
- POST /v1/passport/issuance/offers/{offer_id}/revoke

Wallet-facing:
- GET  /.well-known/openid-credential-issuer
- GET  /v1/passport/issuance/offers/{offer_id}/credential-offer
- POST /v1/passport/issuance/token
- POST /v1/passport/issuance/credential
```

Source: ARC route and registry patterns in `crates/arc-cli/src/trust_control.rs`
and `crates/arc-cli/src/passport_verifier.rs`; OpenID4VCI metadata, token, and
credential endpoint model in sections 4, 6, 8, and 12.

### Anti-Patterns to Avoid

- **Advertising `ldp_vc`:** ARC's current proof semantics do not match the
  OpenID4VCI `ldp_vc` profile.
- **Issuing multiple credential configurations in Phase 53:** one config keeps
  token scope, validation, and tests small.
- **Embedding offer state only in memory:** restarts would silently weaken the
  replay boundary.
- **Treating `credential_issuer` URL as authority by itself:** ARC authority
  still lives in `did:arc` and its signing key.
- **Adding public issuer discovery:** `credential_offer_uri` is enough; no
  directory or marketplace should be introduced.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| External issuance transport | A bespoke ARC-only download flow | OID4VCI offer, token, and credential endpoints | External tooling expects this shape, and it gives ARC a standard issuance contract without changing artifact truth. |
| Replay protection | In-memory "used code" flags | SQLite single-use state machine modeled after `PassportVerifierChallengeStore` | ARC already has a durable consume-once pattern; reuse it. |
| Standard VC compatibility claim | Relabeling ARC passports as `ldp_vc` or `jwt_vc_json` | A custom ARC credential format profile | Prevents false interoperability claims and signature verification mismatch. |
| HTTPS-to-DID trust binding | Implicit trust in an HTTPS hostname | Explicit `credential_issuer` to `did:arc` binding in metadata/profile and exact URL checks | Keeps ARC's self-certifying trust model intact. |
| New subject-binding model | A second ARC holder-binding protocol in Phase 53 | Existing `did:arc` subject plus offer-bound subject validation and optional `tx_code` | Delivery is in scope; broader holder transport is Phase 55. |

**Key insight:** The safest path is "standard issuance flow, ARC-specific
payload" rather than "generic VC payload, ARC-specific trust exceptions."

## Common Pitfalls

### Pitfall 1: Mislabeling ARC Passports as `ldp_vc`

**What goes wrong:** Wallets and verifiers will interpret the proof according
to W3C Data Integrity linked-data rules and reject or mis-handle the ARC
artifact.

**Why it happens:** ARC's current credentials look VC-shaped and already use
`Ed25519Signature2020`, but ARC signs canonical JSON bytes instead of the
linked-data canonicalization expected by the OpenID4VCI `ldp_vc` profile.

**How to avoid:** Define a custom ARC credential format profile for Phase 53.

**Warning signs:** `format: "ldp_vc"` appears anywhere in ARC metadata or
offers; proof verification is described as generic VC Data Integrity.

### Pitfall 2: Silent Trust Shift from `did:arc` to HTTPS

**What goes wrong:** The operator's web endpoint starts acting as the trust
anchor instead of the self-certifying ARC issuer identity.

**Why it happens:** OID4VCI requires an HTTPS `credential_issuer` identifier,
while ARC credentials currently identify issuers as `did:arc`.

**How to avoid:** Include an explicit ARC binding between the HTTPS
`credential_issuer` base and the ARC issuer DID or signing key, and reject
mismatches.

**Warning signs:** Metadata can change issuer identity without changing any ARC
signing key material.

### Pitfall 3: Plain HTTP Remote Deployment

**What goes wrong:** The remote flow is not actually OID4VCI-compatible,
because issuer metadata and endpoints are required to use HTTPS URLs.

**Why it happens:** ARC trust-control currently serves plain HTTP and prints an
`http://` listening URL.

**How to avoid:** Require `--advertise-url` to be HTTPS when remote issuance is
enabled and assume TLS termination at an operator-controlled edge or reverse
proxy.

**Warning signs:** `credential_issuer` or `credential_endpoint` is emitted as
`http://...`.

### Pitfall 4: Weak Pre-Authorized Offer Boundaries

**What goes wrong:** Shoulder-surfed QR codes, cached `credential_offer_uri`
responses, or replayed pre-authorized codes allow duplicate or unintended
issuance.

**Why it happens:** The pre-authorized-code flow is intentionally lighter than
the authorization-code flow and is not session-bound like PKCE.

**How to avoid:** Make pre-authorized codes single use, short lived, unique per
offer, and hashed at rest; require `tx_code` by default for remote offers; set
`Cache-Control: no-store`.

**Warning signs:** Offers survive restart without explicit state, or the same
offer can mint multiple access tokens.

### Pitfall 5: Overclaiming Later-Phase Capability

**What goes wrong:** Docs imply ARC already ships portable status, revocation,
wallet presentation, or qualified external wallet interoperability.

**Why it happens:** OID4VCI adds a recognizable ecosystem vocabulary, which can
make the shipped surface sound broader than it is.

**How to avoid:** Keep docs explicit that Phase 53 covers issuance and
delivery only; leave status portability to Phase 54, holder transport to Phase
55, and qualification to Phase 56.

**Warning signs:** Any phase-53 doc promises revocation portability, wallet
presentation, or verifier qualification.

### Pitfall 6: Further Expanding `trust_control.rs`

**What goes wrong:** The largest existing file gets even harder to own and
future interop work becomes riskier.

**Why it happens:** Adding a small set of endpoints is tempting to do inline.

**How to avoid:** Keep route wiring in `trust_control.rs`, but move offer
store, request validation, and response assembly into a smaller helper module.

**Warning signs:** OID4VCI state management and validation logic is embedded
directly in giant route handlers.

## Code Examples

Verified patterns from official sources:

### Pre-Authorized Credential Offer

```json
{
  "credential_issuer": "https://trust.example.com",
  "credential_configuration_ids": ["ArcAgentPassportV1"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "single-use-short-lived-code",
      "tx_code": {
        "length": 6,
        "input_mode": "numeric"
      }
    }
  }
}
```

Source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html

### Token Request for the Pre-Authorized Flow

```http
POST /v1/passport/issuance/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&
pre-authorized_code=single-use-short-lived-code&
tx_code=493536
```

Source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html

### Minimal ARC Credential Issuer Metadata

```json
{
  "credential_issuer": "https://trust.example.com",
  "credential_endpoint": "https://trust.example.com/v1/passport/issuance/credential",
  "credential_configurations_supported": {
    "ArcAgentPassportV1": {
      "format": "application/arc-passport+json",
      "scope": "arc_agent_passport_v1"
    }
  }
}
```

Source: OpenID4VCI 1.0 metadata requirements plus ARC-specific format profile
inference from the specification's extension points.

### RFC 8785-Aligned Future Compatibility Direction

```json
{
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022"
  }
}
```

Source: https://www.w3.org/TR/vc-di-eddsa/

This is not a Phase 53 implementation requirement. It is the standards-aligned
upgrade path if ARC later decides to move from a custom profile toward broader
generic VC-format compatibility without adopting linked-data canonicalization.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Raw ARC file or API retrieval only | OID4VCI 1.0 offer, token, and credential exchange | OpenID4VCI 1.0 final, 2025-09-16 | Gives ARC a standards-legible issuance contract. |
| Treating all VC-shaped JSON as generic VC interop | Format-specific issuance profiles with explicit processing rules | OpenID4VCI 1.0 final, 2025-09-16 | ARC can stay truthful by using a custom format profile. |
| `ldp_vc` as the assumed Data Integrity path | `ldp_vc` is only for Data Integrity plus JSON-LD plus linked-data canonicalization; non-JSON-LD DI needs separate profiles | OpenID4VCI 1.0 final, 2025-09-16 | ARC must not advertise `ldp_vc` for its current canonical-JSON proof model. |
| Linked-data canonicalization as the closest Ed25519 proof path | `eddsa-jcs-2022` provides a W3C-standard RFC 8785 path | W3C Data Integrity EdDSA v1.0, 2025-05-15 | Future ARC proof modernization can align with current canonical-JSON practice more naturally. |
| Broad wallet interop as one step | Base OID4VCI and high-assurance HAIP ecosystems diverge materially | HAIP 1.0 final, 2025-12-24 | Phase 53 should not claim HAIP or qualified wallet compatibility. |

**Deprecated/outdated:**

- Anonymous raw passport download links as the interop story: replace with
  single-use pre-authorized offers.
- Claiming generic `ldp_vc` compatibility for ARC passports: incorrect until
  ARC uses standard DI semantics and completes external qualification.

## Open Questions

1. **Should Phase 53 issue only full passports or also individual reputation credentials?**
   - What we know: existing verifier policy, lifecycle, and challenge flows are built around `AgentPassport`.
   - What's unclear: whether any near-term consumer truly needs single-credential granularity before Phase 56.
   - Recommendation: ship `ArcAgentPassportV1` only in Phase 53.

2. **Should remote offers always require a `tx_code`?**
   - What we know: OID4VCI explicitly recommends transaction codes to mitigate pre-authorized-code replay.
   - What's unclear: how much friction operators will tolerate for same-device testing or tightly controlled partner pilots.
   - Recommendation: require `tx_code` by default for trust-control-issued offers; allow explicit opt-out only for local operator testing.

3. **Where should ARC publish the HTTPS-to-`did:arc` issuer binding?**
   - What we know: OID4VCI allows issued credentials to use a DID while the `credential_issuer` identifier remains HTTPS.
   - What's unclear: whether the cleanest first implementation is metadata-only, a DID service entry, or both.
   - Recommendation: metadata plus ARC profile binding now; defer broader DID-web binding work unless Phase 56 interoperability demands it.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust `cargo test` workspace tests |
| Config file | none |
| Quick run command | `cargo test -p arc-credentials --lib && cargo test -p arc-cli --test passport` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| VC-01 | ARC emits OID4VCI-shaped metadata, offer, token, and credential contracts that deliver an ARC passport through one interoperable flow | unit + integration | `cargo test -p arc-credentials --lib && cargo test -p arc-cli --test passport` | ✅ |
| VC-05 | Unsupported profile ids, subject mismatches, replay, stale offers, wrong `tx_code`, and insecure metadata fail closed without widening trust | unit + integration | `cargo test -p arc-credentials --lib && cargo test -p arc-cli --test passport` | ✅ |

### Sampling Rate

- **Per task commit:** `cargo test -p arc-credentials --lib && cargo test -p arc-cli --test passport`
- **Per wave merge:** `cargo test -p arc-cli --test passport`
- **Phase gate:** `cargo test --workspace` must be green before `/gsd:verify-work`

### Wave 0 Gaps

None — existing test infrastructure covers this phase. Extend existing files:

- `crates/arc-credentials/src/tests.rs` for typed contract and validation cases
- `crates/arc-cli/tests/passport.rs` for CLI and trust-control round-trips

## Sources

### Primary (HIGH confidence)

- `crates/arc-credentials/src/challenge.rs` - ARC credential signing, passport assembly, and fail-closed verification rules
- `crates/arc-credentials/src/passport.rs` - passport, lifecycle, and policy data model
- `crates/arc-cli/src/passport.rs` - local issuance, challenge, evaluation, and lifecycle command patterns
- `crates/arc-cli/src/trust_control.rs` - trust-control route patterns, `advertise_url` behavior, and existing public/private endpoint split
- `crates/arc-cli/src/passport_verifier.rs` - file-backed registries and SQLite single-use challenge-store pattern
- `crates/arc-did/src/lib.rs` - self-certifying `did:arc` resolution and service attachment model
- `docs/AGENT_PASSPORT_GUIDE.md` - current shipped passport scope and explicit alpha boundary
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` - current portability boundaries and non-goals
- `spec/PROTOCOL.md` - explicit shipped protocol gaps, especially around wallet distribution
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html - current OID4VCI offer, token, credential, metadata, and security rules
- https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html - current HAIP scope and why Phase 53 should not overclaim high-assurance wallet interoperability
- https://www.w3.org/TR/vc-data-model-2.0/ - current VC data model, securing mechanisms, and evidence semantics
- https://www.w3.org/TR/vc-di-eddsa/ - current EdDSA Data Integrity proof model and `eddsa-jcs-2022`

### Secondary (MEDIUM confidence)

- `docs/research/DEEP_RESEARCH_1.md` - milestone rationale for OID4VCI and wallet-mediated portability
- `.planning/PROJECT.md` - project-level milestone framing and boundary promises

### Tertiary (LOW confidence)

- None

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - recommendation stays on existing ARC crates and verified current official OID4VCI/W3C specs.
- Architecture: HIGH - directly matches ARC's established "typed contracts first, CLI and trust-control transport second" pattern.
- Pitfalls: HIGH - most major risks are explicitly called out in OID4VCI security sections and ARC boundary docs.

**Research date:** 2026-03-27
**Valid until:** 2026-04-26
