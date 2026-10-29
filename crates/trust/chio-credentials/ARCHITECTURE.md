# chio-credentials architecture

## Responsibility and boundary

The crate owns native reputation credentials, unsigned passport bundles,
verifier policies, holder presentations, cross-issuer artifacts, discovery,
portable reputation, and bounded JWT credential profiles.
Its financial surface adds signed source manifests, selected membership proofs, verified
policies, authority registries, and lifecycle/source resolver interfaces.

A signed claim establishes integrity under a key. Admission also depends on
trusted issuer selection, policy, fresh lifecycle evidence, and verified source
inputs. HTTP handlers, durable challenge storage, and runtime dispatch belong
to consuming crates.

## Structure

`src/lib.rs` uses `include!` for these files in one shared root namespace:

| Source | Responsibility |
| --- | --- |
| `artifact.rs`, `passport.rs` | Credentials, evidence, passport and lifecycle contracts. |
| `challenge.rs`, `presentation.rs` | Issuance, passport verification, policy evaluation, holder proofs. |
| `policy.rs`, `registry.rs` | Threshold checks and signed verifier policy helpers. |
| `cross_issuer.rs` | V1 portfolio integrity, migration and trust-pack artifacts. |
| `portable_sd_jwt.rs`, `portable_jwt_vc.rs` | Native-derived portable credential projections. |
| `oid4vci.rs`, `oid4vp.rs` | Bounded issuance metadata, offers, and presentation transport profiles. |
| `discovery.rs`, `portable_reputation.rs` | Signed discovery and locally weighted reputation evaluation. |
| `financial.rs`, `financial/validation.rs` | Financial envelopes, decoding, evidence and completeness contracts. |
| `financial/agent_passport.rs` | Source manifests, membership, selectors, holder presentation inspection. |
| `financial/authority/` | Pinned keys, verified policy, lifecycle rollback defenses, financial evaluation. |

`jwt_decode` centralizes compact-JWT parsing; `trust_tier` derives a tier from
compliance score and anomaly status. `fuzz` exposes optional parser harnesses.

## Data and control flow

Reputation issuance derives issuer and subject DIDs from Ed25519 keys and signs
canonical unsigned credential bytes. Passport construction gathers credentials,
checkpoint roots, and enterprise provenance; it does not verify signatures.
Verification checks every credential, matching subject, validity cap, and
aggregated enterprise provenance.

Policy evaluation produces per-credential reasons and accepts if any credential
passes. Native holder responses sign the challenge and selected passport.
Verification checks proof purpose, holder key, challenge window and optional
expected challenge, then evaluates a resolved or embedded policy.
It returns replay state unset and does not consume a nonce.

Portable JWT and SD-JWT lanes derive claims from verified native passports.
Their verifiers use caller-supplied issuer keys and format-specific time and
claim checks. OID4VP additionally binds signed request and holder response
material; service-side request consumption remains a separate concern.

Financial passport presentations bind selected credential digests to a signed source
manifest via membership proofs and selector matching.
`evaluate_financial_credentials` reads a trusted clock, checks verified policy
validity, pins manifest and issuer keys, resolves source evidence, and validates
lifecycle results with generation and high-water anchors.

## Trust and invariants

`verify_agent_passport` takes a verifier-held trusted issuer set. An empty set is
refused, and every credential issuer must be a member before any signature is
checked. `inspect_agent_passport_structure` runs the structural checks without
signature or issuer trust; holder-side presentation and record lookups use it.
`verify_agent_passport` checks credential time windows and caps passport validity
against their minimum expiry. It does not independently enforce the outer
passport's issued-at field or reject a shorter outer validity already in the past.
The bundle's Merkle-root list and optional trust tier are unsigned outer metadata;
credential evidence supplies the roots counted by verification.

Signed policy verification checks shape and signature using its carried key.
`ensure_signed_passport_verifier_policy_active` only checks its time window.
Consumers must combine these checks and pin the verifier authority.
Native `evaluate_agent_passport` does not enforce `require_active_lifecycle`;
current lifecycle admission requires consumer or financial authority evaluation.

Financial decoding performs bounded, duplicate-aware signed JSON parsing and
schema/family dispatch, then contract validation. It does not establish local
issuer admission. Signature inspection is separate from authority evaluation.
Source completeness covers a signed source index and bounded query range,
including adjacent or edge proofs; it cannot prove omitted off-index events.
The bundled resolver supports bundled evidence; external lookup needs another
`FinancialEvidenceSourceResolver` implementation.

Cross-issuer portfolios carry integrity only; activation goes through the
financial trust pack. Financial evaluation rejects reputation credentials.
Settlement-reliability credentials are
rejected at financial schema preflight. Financial authority exposes explicit resolver,
clock, and persistence interfaces instead of supplying deployment services.
Whole-credential selection and JWT disclosures can reveal identifiers and
correlatable evidence; these APIs make no general anonymity guarantee.

## Dependencies

`chio-core` supplies canonical signing, Merkle proofs, and identity context;
`chio-did` restricts native identities to `did:chio`.
`chio-reputation` supplies scorecards, `chio-fincred` and `chio-credit` supply
financial types, and `chio-revocation-oracle` supplies the lifecycle event bridge.
`chrono`, Serde, base64, SHA-256, and randomness support time and JWT encoding.

## Verification

Run `cargo test -p chio-credentials` for native round trips, negative schemas,
passport properties, portable profiles, trust tiers, financial membership and authority.
Tests include credential tampering, selector substitution, invalid holder proofs,
source-manifest metadata, lifecycle replay, and issuer authority fixtures.
Run `cargo test -p chio-credentials --features dudect --release --test dudect_jwt_verify`
for the opt-in JWT verifier timing harness. It is statistical timing evidence.
The crate has no benchmarks; timing instrumentation is a separate test target.
