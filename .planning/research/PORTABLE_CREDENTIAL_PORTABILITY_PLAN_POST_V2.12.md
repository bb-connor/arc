# Post-v2.12 Portable Credential Portability Plan

**Project:** ARC  
**Scope:** Close the remaining DID/VC portability gaps beyond the shipped OID4VCI-compatible path  
**Researched:** 2026-03-28  
**Overall confidence:** MEDIUM-HIGH

## Executive Recommendation

ARC should treat the remaining portability work as **two milestones**, not one:

1. **v2.13 Portable Credential Format and Lifecycle Convergence**
2. **v2.14 OID4VP Verifier and Wallet Interop**

The key product choice is to **standardize one external portable path well** instead of claiming the whole wallet ecosystem. The recommended path is:

- keep the current ARC-native `AgentPassport` path as the high-fidelity internal and federation artifact
- add **SD-JWT VC** as the first standards-native external credential format
- add **OID4VP** as the first generic presentation protocol
- keep **SIOPv2 optional and explicitly non-gating**
- keep **public wallet networks, DIDComm, and generic DID method expansion out of scope**

This is the smallest plan that is still honest enough to say ARC achieved the research idea from `docs/research/DEEP_RESEARCH_1.md`: portable passports become real through a standards-native issuance format, selective disclosure, portable lifecycle/status, and verifier-facing presentation interoperability.

## Why This Plan Fits ARC

Current ARC already proves a narrow interop lane:

- OID4VCI-compatible issuance is shipped at `/.well-known/openid-credential-issuer`, `/v1/passport/issuance/token`, and `/v1/passport/issuance/credential` ([docs/CREDENTIAL_INTEROP_GUIDE.md](/Users/connor/Medica/backbay/standalone/arc/docs/CREDENTIAL_INTEROP_GUIDE.md#L6))
- public holder transport exists only through ARC-native challenge fetch and submit routes ([docs/CREDENTIAL_INTEROP_GUIDE.md](/Users/connor/Medica/backbay/standalone/arc/docs/CREDENTIAL_INTEROP_GUIDE.md#L43))
- ARC still explicitly does **not** ship generic OID4VP/SIOP, SD-JWT, or public verifier discovery ([docs/CREDENTIAL_INTEROP_GUIDE.md](/Users/connor/Medica/backbay/standalone/arc/docs/CREDENTIAL_INTEROP_GUIDE.md#L55))
- the portable trust profile still excludes public wallet distribution and requires holder transport to remain ARC-native ([docs/standards/ARC_PORTABLE_TRUST_PROFILE.md](/Users/connor/Medica/backbay/standalone/arc/docs/standards/ARC_PORTABLE_TRUST_PROFILE.md#L13), [docs/standards/ARC_PORTABLE_TRUST_PROFILE.md](/Users/connor/Medica/backbay/standalone/arc/docs/standards/ARC_PORTABLE_TRUST_PROFILE.md#L119))
- the current credential crate still describes the format as intentionally simple, `did:arc`-bound, and bundle-oriented ([crates/arc-credentials/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-credentials/src/lib.rs#L1))
- `v2.11` passed with those remaining gaps still called out as residual non-goals ([.planning/milestones/v2.11-MILESTONE-AUDIT.md](/Users/connor/Medica/backbay/standalone/arc/.planning/milestones/v2.11-MILESTONE-AUDIT.md#L26))

That means ARC is not missing "more code around the current path"; it is missing **a second, standards-native path**.

## Recommended Milestone Sequencing

### v2.13 Portable Credential Format and Lifecycle Convergence

**Goal:** Add one standards-native credential format and portable lifecycle semantics without replacing the current ARC-native passport contract.

**Why first:** OID4VP without a wallet-legible credential format does not close the actual portability gap. ARC must first issue something mainstream wallets and verifiers can parse.

**Recommended requirement IDs:**

- `PVC-01`: ARC issues at least one standards-native portable credential format in addition to `arc-agent-passport+json`.
- `PVC-02`: ARC selective disclosure is policy-bounded and verifier-request-driven rather than ad hoc field filtering.
- `PVC-03`: Portable type metadata, issuer metadata, and public key material are published at stable HTTPS locations with integrity/version rules.
- `PVC-04`: Status, revocation, and supersession map from operator truth into portable status artifacts without inventing a new trust root.
- `PVC-05`: ARC-native passport, challenge, and federation flows remain supported and fail closed when external-format requests are unsupported.

#### Phase 61: External Credential Projection and Identity Strategy

**Depends on:** Phase 60  
**Scope:**

- define the first external portable credential as an **SD-JWT VC projection** of the current ARC passport truth
- choose the external identifier model:
  - portable issuer identity: HTTPS issuer URL plus JWKS / JWT VC issuer metadata
  - holder binding: key-bound SD-JWT VC, not a new global `did:arc` dependency
  - ARC-native `did:arc` remains as internal/native identity and may be carried only as an ARC-specific claim or provenance reference
- define one `vct` and type-metadata document for the external ARC passport profile
- define how enterprise provenance, runtime assurance, and certification references appear in the projection without silently widening trust

**Recommendation:** do **not** try to make the current unsigned multi-credential `AgentPassport` bundle itself the standards-native VC. Treat the external credential as a projection over existing passport truth plus provenance links.

#### Phase 62: SD-JWT VC Issuance and Selective Disclosure Profile

**Depends on:** Phase 61  
**Scope:**

- add a second OID4VCI credential configuration for `application/dc+sd-jwt`
- issue one ARC-defined SD-JWT VC type with explicit disclosure rules
- support holder key binding and verifier validation rules
- define the minimal selectively disclosable claim catalog:
  - subject binding
  - issuer and issuance timestamps
  - bounded reputation / score band or categorical claims
  - enterprise provenance facts that are safe to disclose
  - runtime assurance and certification references as optional disclosed claims
- define which claims are never selectively disclosable, especially issuer, status, validity, and provenance anchors

**Recommendation:** target **SD-JWT VC first** and defer JSON-LD/Data Integrity and mdoc. That is the lowest-cost path with the strongest current OID4VCI/OID4VP conformance momentum.

#### Phase 63: Portable Status, Revocation, and Type Metadata

**Depends on:** Phase 62  
**Scope:**

- define the public status publication contract for the SD-JWT VC profile
- map current ARC lifecycle truth (`active`, `superseded`, `revoked`, `notFound`, stale) into portable verifier semantics
- publish stable type metadata and integrity values for ARC `vct` documents
- define cache rules, stale-data handling, and replacement/supersession semantics
- preserve the current operator-scoped lifecycle resolve plane as the source of truth

**Recommendation:** use **IETF Token Status List (TSL)** for the SD-JWT VC path, with ARC lifecycle APIs remaining the richer operator truth. `superseded` should stay an ARC lifecycle concept even if the portable status surface only communicates a verifier-fail state plus replacement metadata.

#### Phase 64: Portable Credential Qualification and Boundary Rewrite

**Depends on:** Phase 63  
**Scope:**

- add unit and integration coverage for SD-JWT VC issuance, disclosure, metadata, and status validation
- extend `docs/CREDENTIAL_INTEROP_GUIDE.md`, `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`, `spec/PROTOCOL.md`, and qualification docs to document the new dual-path model
- add one external raw-HTTP qualification lane for SD-JWT VC issuance and validation
- keep the current `arc-agent-passport+json` lane documented as supported but narrower

**Milestone acceptance criteria:**

1. An external client can obtain an ARC credential through OID4VCI in either the current ARC-native format or the new SD-JWT VC format.
2. The SD-JWT VC path exposes stable issuer metadata, type metadata, and status artifacts with fail-closed validation.
3. Selective disclosure is deterministic, bounded, and covered by negative tests.
4. ARC docs explicitly state which portable claims are standards-native and which remain ARC-native only.

**Validation / qualification evidence:**

- ARC unit tests for SD-JWT VC encoding, disclosure verification, and metadata validation
- ARC integration tests for issuance, status resolution, revoked/superseded handling, and malformed metadata rejection
- one raw-HTTP proof that a non-CLI client can mint and validate the SD-JWT VC path
- updated qualification table alongside the current OID4VCI and ARC-native presentation rows in [docs/release/QUALIFICATION.md](/Users/connor/Medica/backbay/standalone/arc/docs/release/QUALIFICATION.md#L109)

### v2.14 OID4VP Verifier and Wallet Interop

**Goal:** Make ARC a standards-native verifier surface for portable passport presentations and prove at least one real wallet path end to end.

**Why second:** Once ARC can issue a wallet-legible credential, it can add a generic presentation flow without pretending the whole wallet ecosystem is solved.

**Recommended requirement IDs:**

- `PVP-01`: ARC can act as an OID4VP verifier for the ARC SD-JWT VC profile.
- `PVP-02`: ARC supports one pragmatic verifier-authentication profile suitable for public web verifier deployment.
- `PVP-03`: ARC supports same-device and cross-device wallet invocation without requiring a proprietary ARC holder transport.
- `PVP-04`: ARC proves one external wallet round trip with portable status checks, selective disclosure, and replay-safe verification.
- `PVP-05`: ARC remains explicit about unsupported ecosystems such as DIDComm, public wallet directories, and generic trust registries.

#### Phase 65: OID4VP Verifier Profile and Request Transport

**Depends on:** Phase 64  
**Scope:**

- add OID4VP request-object creation, signing, and replay-safe verifier transaction storage
- support request-by-reference via `request_uri`
- support cross-device QR and same-device redirect flows
- support DCQL-based credential requests for the ARC SD-JWT VC profile
- define verifier-side response handling and fail-closed nonce / audience / state validation

**Recommendation:** make **`request_uri` + `direct_post.jwt`** the primary transport profile. It fits QR-based cross-device flows and keeps the request object signed and auditable.

#### Phase 66: Wallet / Holder Distribution Adapters

**Depends on:** Phase 65  
**Scope:**

- add a minimal reference holder adapter for qualification and partner demos
- add wallet launch artifacts for same-device and cross-device use
- optionally add a browser **Digital Credentials API** adapter behind a feature flag or experimental boundary
- define how existing ARC-native challenge flows coexist with the OID4VP path

**Recommendation:** ARC should ship a **reference holder test app / SDK adapter**, not a production consumer wallet. The point is qualification and partner integration, not becoming a wallet vendor.

#### Phase 67: Public Verifier Trust and Discovery Model

**Depends on:** Phase 65  
**Scope:**

- choose one verifier-authentication and discovery model for public deployment
- publish verifier metadata, certificates, or attestation artifacts as required
- document trust bootstrap and verifier-key rotation
- define which verifier-identity schemes ARC accepts and which it rejects

**Recommendation:** support **`x509_san_dns` first** for OID4VP verifier identity. It fits ARC's operator-scoped web deployment model and avoids forcing immediate DID or OpenID Federation support. Consider `verifier_attestation` only as a second profile when a partner ecosystem requires it.

#### Phase 68: Ecosystem Qualification and Research Closure

**Depends on:** Phases 66 and 67  
**Scope:**

- run end-to-end issuance plus presentation qualification against at least one external wallet or verifier stack
- add negative-path coverage for stale status, invalid verifier identity, replay, unsupported `client_id` schemes, and over-disclosure
- rewrite the portability boundary docs and milestone audit language so ARC can honestly claim the research idea is achieved
- update planning state so post-v2.14 work is clearly optional expansion, not "core portability still missing"

**Milestone acceptance criteria:**

1. ARC can verify an SD-JWT VC presentation through OID4VP without relying on ARC-native holder challenge artifacts.
2. ARC supports one documented same-device flow and one documented cross-device QR flow.
3. At least one external wallet path passes end-to-end issuance, selective disclosure, status checking, and verifier validation.
4. Unsupported verifier identity schemes, unsupported credential formats, stale status, replay, and trust-bootstrap failures are all fail-closed.
5. ARC docs no longer need to say OID4VP, SD-JWT, and public verifier interop are missing.

**Validation / qualification evidence:**

- local ARC regression suite for OID4VP request generation, response verification, and replay handling
- one external-wallet conformance lane recorded in release qualification
- preferably OIDF self-certification or conformance logs for the implemented OID4VCI / OID4VP subset
- partner-proof example showing QR or redirect presentation into an ARC verifier surface

## Explicit Non-Goals

- no DIDComm or proprietary mobile-wallet messaging stack
- no global wallet or verifier discovery network
- no public mutable trust registry or synthetic cross-issuer trust score
- no requirement that `did:arc` become a universally resolvable external DID method in this cycle
- no requirement to support every VC proof family; **SD-JWT VC is the first-class target**
- no requirement to become a full production wallet product
- no default claim of HAIP certification

## Decision Points Where ARC May Intentionally Stay Narrower

### 1. SIOPv2

**Recommendation:** do not make generic SIOPv2 support a milestone gate.  
**Reason:** OID4VP 1.0 is final and active; SIOPv2 is still draft 13 from November 2023 and was listed by the OpenID Foundation as an inactive specification in April 2025.

### 2. DID Strategy

**Recommendation:** do not block portable credential completion on a global `did:arc` rollout.  
**Reason:** the shipped repo still treats `did:arc` resolution as local and self-certifying ([spec/PROTOCOL.md](/Users/connor/Medica/backbay/standalone/arc/spec/PROTOCOL.md#L118)). ARC can complete the standards-native path with HTTPS issuer identifiers and key-bound holder credentials first.

### 3. Verifier Authentication

**Recommendation:** implement `x509_san_dns` first, keep `verifier_attestation` optional, and defer DID-based or OpenID Federation verifier identity unless an ecosystem requires it.

### 4. Digital Credentials API

**Recommendation:** treat the W3C Digital Credentials API as an optional adapter, not the core milestone gate.  
**Reason:** it is promising for browser-mediated same-device flows but is still a W3C Working Draft, not a stable deployment baseline.

### 5. HAIP

**Recommendation:** do not make full HAIP conformance the initial closure criterion.  
**Reason:** HAIP is valuable, but its X.509 and attestation expectations are a larger policy and PKI choice than ARC needs for first portability closure.

## Specific References Back to ARC Research and Current State

### ARC research and planning references

- `docs/research/DEEP_RESEARCH_1.md` positions DID/VC as the portable identity layer and places portable passports in the 2027+ portion of the roadmap ([docs/research/DEEP_RESEARCH_1.md](/Users/connor/Medica/backbay/standalone/arc/docs/research/DEEP_RESEARCH_1.md#L168), [docs/research/DEEP_RESEARCH_1.md](/Users/connor/Medica/backbay/standalone/arc/docs/research/DEEP_RESEARCH_1.md#L292), [docs/research/DEEP_RESEARCH_1.md](/Users/connor/Medica/backbay/standalone/arc/docs/research/DEEP_RESEARCH_1.md#L490))
- post-`v2.12` planning is currently undefined, so this work can cleanly become the next roadmap entry ([.planning/PROJECT.md](/Users/connor/Medica/backbay/standalone/arc/.planning/PROJECT.md#L20), [.planning/ROADMAP.md](/Users/connor/Medica/backbay/standalone/arc/.planning/ROADMAP.md#L1), [.planning/REQUIREMENTS.md](/Users/connor/Medica/backbay/standalone/arc/.planning/REQUIREMENTS.md#L1))
- the `v2.11` audit explicitly leaves OID4VP, SD-JWT, and public verifier discovery as open gaps ([.planning/milestones/v2.11-MILESTONE-AUDIT.md](/Users/connor/Medica/backbay/standalone/arc/.planning/milestones/v2.11-MILESTONE-AUDIT.md#L26))

### ARC code and doc references

- narrow shipped interop boundary and non-goals: [docs/CREDENTIAL_INTEROP_GUIDE.md](/Users/connor/Medica/backbay/standalone/arc/docs/CREDENTIAL_INTEROP_GUIDE.md#L55)
- operator-scoped portability boundary and fail-closed rules: [docs/standards/ARC_PORTABLE_TRUST_PROFILE.md](/Users/connor/Medica/backbay/standalone/arc/docs/standards/ARC_PORTABLE_TRUST_PROFILE.md#L59)
- current `did:arc` and ARC-native protocol identity model: [spec/PROTOCOL.md](/Users/connor/Medica/backbay/standalone/arc/spec/PROTOCOL.md#L118)
- current OID4VCI format is custom `arc-agent-passport+json`: [crates/arc-credentials/src/oid4vci.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-credentials/src/oid4vci.rs#L1)
- current credential crate is intentionally simple, `did:arc`-bound, and bundle-oriented: [crates/arc-credentials/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-credentials/src/lib.rs#L1)
- current qualification already proves OID4VCI issuance and ARC-native holder transport, which should remain as baseline regression coverage: [docs/release/QUALIFICATION.md](/Users/connor/Medica/backbay/standalone/arc/docs/release/QUALIFICATION.md#L109)

## External Standards Inputs

- **OpenID4VP 1.0** is final and supports verifier request objects, `request_uri`, multiple verifier identifier schemes, DCQL, redirect flows, and W3C Digital Credentials API integration.
- **OpenID4VCI 1.0**, **OpenID4VP 1.0**, and **HAIP 1.0** are in the OpenID Foundation self-certification program launched in February 2026, with tests covering SD-JWT and mdoc presentation and SD-JWT issuance first.
- **SD-JWT VC** is the active selective-disclosure credential format path, using media type `application/dc+sd-jwt`, type metadata, and optional JWT VC issuer metadata.
- **W3C VC 2.0**, **JOSE/COSE for VC**, and **Bitstring Status List v1.0** are W3C Recommendations as of 2025.
- **SIOPv2** remains a draft from November 2023 and has not advanced at the same pace as OID4VP.
- **W3C Digital Credentials API** is promising for browser-mediated wallet invocation, but it is still a Working Draft.

## Source URLs

- OpenID4VP 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OpenID4VCI 1.0 / OIDF self-certification announcement: https://openid.net/openid-for-verifiable-credential-self-certification-to-launch-feb-2026/
- HAIP 1.0 final: https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html
- SIOPv2 draft 13: https://openid.net/specs/openid-connect-self-issued-v2-1_0.html
- OIDF April 2025 Connect WG update noting inactive SIOPv2: https://openid.net/wp-content/uploads/2025/04/Pre-IIW-Workshop-Slide-Deck-07April2025.pdf
- SD-JWT VC datatracker: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- W3C VC 2.0 family Recommendation announcement: https://www.w3.org/news/2025/the-verifiable-credentials-2-0-family-of-specifications-is-now-a-w3c-recommendation/
- W3C Digital Credentials API Working Draft: https://www.w3.org/TR/digital-credentials/
