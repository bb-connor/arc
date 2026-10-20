# Relying-party wedge: Chio in front of MCP servers and paid APIs

Status: APPROVED by the founder, revision 3. Design doc. No code in this document is implemented unless a row says otherwise.

Repository state read for this spec: `origin/main` at `d0482967b8` (after #1513). No cargo commands were run. Every "today" statement below cites a file read at that commit. Section 2.5 G17 to G19 and facts T26, T29 and T30 were re-read at `d78dfef2dc` (after #1535 and #1540).

Milestones are labeled M0 to M3. Calendar dates for them are kept outside this repository.

## 0. Claim labels

Labels are strict and never upgraded:

- **qualified**: named in `docs/release/QUALIFICATION.md` or approved with scope in `docs/reference/CLAIM_REGISTRY.md`.
- **shipped**: on `main` with tests, outside the qualified boundary.
- **test only**: on `main`, reached only from tests.
- **design doc**: written design, no implementation.
- **roadmap**: direction with no design.
- **absent**: no code found.
- **new (this spec)**: proposed here.

External standards carry a pin note. "Pin at build start" means the builder reads the named primary specification on the first day of the milestone and records the exact revision in code and in the crate README.

## 1. Intent and why

### 1.1 The product in one paragraph

A company that exposes an MCP server or a paid HTTP API puts Chio in front of it. Chio accepts the caller's enterprise identity (an Okta Cross App Access ID-JAG or an ordinary Microsoft Entra application token from M1, a Microsoft Entra Agent ID token from M2), exchanges it for a short-lived, attenuating Chio capability rooted in that identity, mediates every tool call against the capability, and signs one receipt per call. The provider keeps the receipt for its own audit, billing reconciliation and disputes. From M2 the caller also gets its own copy of each receipt with the tool response. The provider can hand a customer tenant a receipt bundle, and the customer verifies it offline with an Apache-2.0 CLI that does not need network access or trust in the provider's database.

### 1.2 Why the relying party

1. **Heterogeneity is forced on the provider.** An agent builder picks one cloud, one IdP and one payment rail. A provider whose MCP server or API is called by other companies' agents cannot pick. Its callers arrive with Okta, Entra, other OIDC issuers and, for paid tools, x402 payments. A component that accepts all of them at one door is a requirement for the provider, and the provider does not need to be persuaded that neutrality matters.
2. **Receipts have a second reader.** Inside one organization the operator holds the signing key, and a signed log adds little against the party an auditor worries about. At a provider boundary there are two parties with opposed interests: the provider and the calling company. A receipt signed at the provider's enforcement point, rooted in the caller's own IdP assertion, and verifiable by the caller without the provider's cooperation is useful to both. The caller can prove what its agent was allowed to do and what it did. The provider can prove it did only what was authorized.
3. **It builds on the most qualified Chio surface.** `chio mcp serve-http` with OAuth bearer, JWT, introspection, DPoP and mTLS confirmation is **qualified** (QUALIFICATION rows for the hosted authorization edge). The wedge changes how that surface issues authority and adds privacy, verification and, from M2, key custody. It adds no runtime adapter for any cloud. Because the issuance path changes, the qualified label is suspended for `serve-http` from the M1 migration merge until the hosted-edge lane re-passes inside M1 (D1), and public docs say so during that window (F13).

### 1.3 What this spec decides

It turns the recommended designs A-3 (anchored roots), D-2 (terminal receipt plus one settlement closure) and E-3 (AuthZEN profile plus a distinct external-enforcement receipt class) from the internal authority-plane brainstorm into buildable v1 wire formats and crate changes, cut down to what a relying party needs through M3. It also makes two protocol-wide changes the wedge depends on: a fixed-size signing wrapper for every Chio canonical-JSON signature, and committed (salted) receipts as the only receipt format. Leases (design B), hierarchical spend lines and cross-domain allocation certificates (design C beyond the typed asset), SCITT registration, multi-instance deployments and runtime adapters are out of scope.

## 2. Decisions

### 2.1 Founder decisions

| # | Decision | Consequence in this spec |
|---|---|---|
| F1 | Customer-hosted token exchange first. A Backbay-hosted exchange comes later. | The exchange runs inside the provider's own `chio mcp serve-http` process (section 6.2). Nothing in v1 depends on a Backbay service. |
| F2 | On-chain assets are allowed in the schema. Settlement on them is rehearsal-only. | `Asset` accepts `caip19:` values. Policy and manifest load reject any CAIP-2 chain id outside a compiled-in testnet allowlist (section 9.7). |
| F3 | The edge accepts only exchange-issued roots in v1. | Every root capability at the edge is signed by a pinned exchange key and carries a `root_anchor`. Self-anchored (proof-of-possession) roots are out of v1. |
| F4 | A terminal receipt plus one settlement closure counts as the joined receipt. | `chio.settlement-closure.v1` (section 7.10). Inline settlement needs no closure. |
| F5 | Default kill latency and capability lifetime are 300 s, configurable. | Root lifetime defaults to 300 s and is further capped by the IdP assertion's `exp`. The 300 s IdP-revocation bound is claimed for ID-JAG only (D5). The full `chio.lease.v1` object is not built; renewal is re-exchange with a fresh assertion. |
| F6 | Cedar is an optional guard crate outside `chio-kernel-core`. | If built, it lives at `crates/guards/chio-cedar-guard` and runs only in the hosted kernel. It is not a milestone deliverable. |
| F7 | P-256 is allowed through a remote KMS signer. Ed25519 stays the default. | AWS KMS backend in M2 (F11). P-256 verification moves into default builds in M2 (section 10.1). |
| F8 | No escrow and no custody. | Chio never holds wallet keys, funds or payment instruments. x402 settlement goes from the caller's wallet to the provider's `payTo` through a third-party facilitator. |
| F9 | `pdp_decision` receipts are signed as a distinct class. | `receipt_kind = "pdp_decision"`, `boundary_class = "prevent_external"`, `trust_level = "delegated"` (section 7.9). |
| F11 | Apply the second-line cuts: the caller copy in `_meta.chioReceipt` moves to M2; AWS KMS P-256 moves to M2, M1 uses seed-file keys only and makes no custody claim; Entra Agent ID moves to M2. M1 is re-sized. | Sections 12, 13. |
| F12 | Entra Continuous Access Evaluation is not scheduled before M3 completes and stays unscheduled roadmap. | Section 3.2. |
| F13 | Public docs and the README state the hosted-edge qualified-label suspension for the whole re-qualification window. | Section 10.10. |
| F14 | Keep useful paths; no compat hacks. Chio has no backward compatibility and every format is v1, but a path that is useful and planned for v1 is kept and mapped onto anchored roots. Only hacks and duplicates are deleted. | The `--auth-token` static bearer stays as the `operator_static_bearer` kind and generic Entra intake stays as the `entra_jwt` kind, both in M1 (D1, D14). Entra Agent ID is added in M2 beside `entra_jwt`. Section 2.4 records the keep-or-delete decision for every existing `serve-http` path. |

F11 to F13 are recorded as: Decided 2026-10-17 (founder). F14 is recorded as: Decided 2026-10-17 (founder): keep useful paths; no compat hacks.

### 2.2 Coordinator decisions

Each row below is recorded as: Decided 2026-10-17 (coordinator call; founder may override).

| # | Decision | Where it lands |
|---|---|---|
| D1 | The relying-party behaviour replaces current `serve-http` issuance for every deployment. No dual paths: every surviving authentication path ends in an exchange-issued anchored root. Under F14 the useful paths are kept and mapped (static bearer, generic OIDC JWT, introspection, generic Entra, the local AS login and re-exchange, trust-control as an exchange signer, and the enterprise provider registry as the one source of provider identity, G17), and the hacks and duplicates are deleted (seed-derived federation subject keys, session issuance that bypasses the exchange, the provider-profile flag and the per-provider verification flags, the per-store database path flags). Section 2.4 lists each. The qualified hosted-edge lane re-runs inside M1; the qualified label is suspended until it passes. Revised: Decided 2026-10-17 (founder): keep useful paths; no compat hacks. | Sections 2.4, 6, 7.2, 10.5, 12 (M1), 13 |
| D2 | Committed receipts are protocol-wide: one receipt format. Every producer gets a salt source from the host RNG through the existing `Rng` seam, including the FFI and WASM signers. Inline-versus-committed disclosure per tool and per field lives in the signed root policy, so a verifier can see that plaintext was authorized. Default is committed. | Sections 7.6, 7.7, 10.2, 10.3, 13 |
| D3 | Revocation v1 extends the existing SQLite revocation store inside the provider process and is read in the admission transaction. Provider-side revocation and IdP-driven expiry land in M1. Caller-side revocation of its own delegated descendants, by a signed revocation request submitted to the provider, lands in M2. | Sections 7.11, 8.2, 10.7 |
| D4 | v1 is single-instance per provider. This is a deployment limit. A shared replay, root and revocation store is roadmap. | Sections 6.1, 8.3, 9.5 |
| D5 | The 300 s IdP-revocation claim covers ID-JAG only. Entra (`entra_jwt` from M1, `entra_agent_id` from M2): one root per Entra token keyed by `uti`, root lifetime capped at `min(300 s, token exp)`, no re-exchange of the same token. IdP revocation of an Entra principal takes effect at token expiry (about one hour). | Sections 6.3, 9.1, 12 |
| D6 | Signing preimage: a fixed-size, domain-separated signing wrapper for every Chio canonical-JSON signature. PROTOCOL text, schemas and conformance vectors land in M0. | Sections 7.0, 10.1, 13 |
| D7 | ID-JAG retention is opt-in per root policy rule, default off. M0 schemas carry the optional slot. | Sections 7.3, 7.4, 11.4 |
| D8 | Export scope: "one customer" means one tenant. The provider keeps an HMAC-keyed tenant index with no plaintext tenant ids. Caller bundles include salts only for that tenant's receipts and principals. | Sections 7.12, 10.7 |
| D9 | `chio api protect` gets anchored roots and root-policy disclosure in M3, together with x402 over HTTP. M1 and M2 relying-party features ship in `serve-http` only. | Sections 6.6, 6.7, 10.8, 12 |
| D10 | Staffing plan: one engineer plus coding agents. The cut list applies from day one of M1, and M1 is ordered for one engineer. | Section 13 |
| D11 | Every MCP tool response carries the signed receipt and the caller's salts in `_meta.chioReceipt` by default, from M2 (F11). | Section 7.6 |
| D12 | Accept a customer-hosted root exchange ADR in M0. Its outline is section 15. | Sections 10.10, 15 |
| D13 | In v1, caps must be denominated in the same asset as the tool price. No conversion and no peg. | Sections 6.7, 8.6 |
| D14 | Entra is admitted through two dedicated kinds. `entra_jwt` (M1) admits ordinary Entra application and workload tokens, with the principal taken from the one claim the provider record's subject mapping names (`oid` for Entra records; G17 replaces the earlier `oid`, `sub`, `azp`, `appid`, `client_id` fallback). `entra_agent_id` (M2) admits Entra Agent ID agent identities and is added beside `entra_jwt`, not in place of it. An `oidc_jwt` rule naming a Microsoft Entra issuer rejects at load, so every Entra token is held to the D5 rules. Revised: Decided 2026-10-17 (founder): keep useful paths; no compat hacks. | Sections 6.3, 7.2, 8.1 |
| D15 | This spec stays in `docs/superpowers/specs/`, with milestone labels instead of calendar dates. | Header |
| D16 | The `SigningBackend` collapse (`public_key() -> Result<PublicKey>`, `algorithm()` and `current_public_key()` deleted, per the parallel lead's plan) folds into M0 as its only Rust code item. It is byte-neutral and lands as one PR before M1 item 1. The signing wrapper, the `sign_canonical_bytes` replacement, the committed receipt fields and `root_anchor` stay in M1; `ClassicalSigner` and KMS stay in M2. | Sections 10.1, 12 (M0), 13 |
| D17 | M0 code starts after #1496 and #1489 land. Any change to `chio.receipt.v1` bytes or the capability signing bytes is coordinated with the parallel lead before its PR opens, because #1489 (DPoP) and coop2c (revocation roots) produce signed artifacts whose fixtures regenerate with it. | Sections 12 (M0), 13.3 |

D16 rationale: the wrapper and committed receipts both replace the trait's canonical signing entry point and touch every signing call site and fixture. Landing the API-only collapse first means M1 item 1 changes bytes once, on the final trait shape, and the KMS backend in M2 gets a fallible identity read (`GetPublicKey` can fail) without a second trait change.

### 2.3 Consequences of these decisions

- **Receipt format in `api protect`.** D2 makes the receipt format protocol-wide, so `chio api protect` emits committed receipts from the M1 format change onward. It has no root policy until M3 (D9), so its receipts are fully committed until then. D9 governs relying-party features (anchored roots, root-policy disclosure, tenant export) for `api protect`.
- **AuthZEN host.** AuthZEN is served by `serve-http` in M2 (D9).
- **Kill latency.** The bound depends on the anchor kind (D5), so roots carry the assertion's `exp` (`assertion_exp`) and verifiers derive the bound.
- **Revocation freshness.** Revocation is a local SQLite read inside the admission transaction (D3), so receipts carry no revocation staleness member.
- **Readiness.** With one instance (D4) there is no failover. Readiness only signals that every call is being denied.
- **M1 custody.** With seed-file keys only in M1 (F11), an attacker who reads the seed files can forge receipts and roots for any time until the key is replaced. Section 9.5 states this, and M1 makes no key-custody claim.

### 2.4 Keep-or-delete decisions for existing `serve-http` paths (F14)

Usage counts are from `git grep` on `origin/main` at `6c76fafe95`, outside `docs/superpowers/`. The enterprise provider registry and verification-flag rows were re-audited at `d78dfef2dc`, after #1535 (G17).

| Path today | Used by | Decision | Reason |
|---|---|---|---|
| `--auth-token` static bearer (`RemoteAuthMode::StaticBearer`) | progressive tutorial, cpp, js, go and python conformance peers, TypeScript, Go, C++ and Python SDK tests, five example networks, `examples/docker`, `scripts/check-sdk-publication-examples.sh`, `scripts/check-sdk-release.sh` | keep and map: `operator_static_bearer` (M1) | dev, test and conformance on-ramp; the token resolves to an operator-issued root naming an operator-configured principal |
| Generic Entra intake (`JwtProviderProfile::AzureAd`) | `chio-mcp-remote` bearer path and tests | keep and map: `entra_jwt` (M1) | dominant enterprise IdP; most agents present ordinary Entra application tokens. The provider's issuer, keys, audience and principal claim live in its provider record (G17) |
| Generic OIDC JWT bearer (`--auth-jwt-public-key`, discovery) | operator runbook onboarding, operations and security docs, `chio-mcp-remote` tests | keep and map: `oidc_jwt` (M1) | standard bearer intake for non-Entra issuers. Its issuer and keys (`jwks_url`, or an inline `jwks` that replaces `--auth-jwt-public-key`) live in its provider record (G17) |
| Introspection bearer (`--auth-introspection-url`) | operations and reference docs, `chio-mcp-remote` tests | keep and map: `oauth_introspection` (M1) | opaque-token issuers have no other path. The endpoint lives in its provider record (G17); the client credentials the edge presents stay `serve-http` secrets |
| Local AS `authorization_code` login | cpp, js, go and python conformance peers, Go, Python and C++ SDK auth clients, `integrations/mcp-adapter` | keep and map: `chio_local_as` (M1) | local users and the conformance auth scenarios |
| Local AS token re-exchange (RFC 8693, `subject_token_type` access token) | `auth-token-exchange-initialize` in the cpp, js and go peers, Go and Python SDK `exchange_token`, the QUALIFICATION hosted-edge row | keep and map: `chio_local_as` re-exchange (M1) | resource and scope narrowing of a local AS token; the exchanged token gets a narrower root (section 7.2) |
| Pinned remote trust-control authority (`--control-url`, `--control-authority-public-key`) | `deploy/reference-runtime` systemd unit, `scripts/check-sdk-publication-examples.sh`, example networks, operator runbook | keep and map: `--exchange-signer trust-control:<url>` (M1); `serve-http` no longer accepts `--control-url` | operators already run `serve-http` against trust-control; it becomes a signer for exchange roots, with its own signing route, credential and trusted keys. `serve-http` keeps every store in `--state-dir`, so it has no remote store mode. The owner decision for this row covers removing every remote store mode of `serve-http` (durable admission, receipts and openings, revocations, budgets and the session authority), not only remote durable admission |
| Session capability issuance that bypasses the exchange (`configure_capability_authority` path in `factory.rs`) | `serve-http` internals only | delete | a second issuance path beside the exchange, excluded by D1 |
| Seed-derived federation subject keys (`derive_federated_agent_keypair`, `derive_enterprise_subject_key` in `chio-mcp-remote`) | `serve-http` session identity and resume only | delete | anyone holding the authority seed can derive every principal's key; session-held roots (section 6.5) replace it. The separate copy in `chio-control-plane` SCIM lifecycle is outside this spec |
| `serve-http` `--enterprise-providers-file` (`chio.enterprise-providers.v1`) | since #1535, every JWT and introspection bearer request in `chio-mcp-remote` reads it once (provider enable and disable, subject mapping, trust material reference, HTTP 503 when unreadable); admin health; trust-control provider admin writes the same format; `chio-mcp-remote` and `chio-cli` tests | keep: the one source of provider identity (M1, G17) | maintained and used. Root policy rules reference a record by `provider_record_id` and pin its identity digest; issuer, keys, endpoint, audience and subject mapping are configured only in the record |
| `serve-http` `--auth-jwt-provider-profile` and the record member `provider_profile` | `chio-mcp-remote` and `chio-cli` tests; the record member is written as `None` | delete | duplicates the rule's `anchor_kind`; the principal claim comes from the record's subject mapping (G17) |
| `serve-http` provider verification flags (`--auth-jwt-public-key`, `--auth-jwt-discovery-url`, `--auth-jwt-issuer`, `--auth-jwt-audience`, `--auth-introspection-url`) | operator runbook, operations and reference docs, `chio-mcp-remote` and `chio-cli` tests | delete; callers move to provider records | a second place to configure issuer, keys, audience and endpoint beside the registry (G17). `--auth-introspection-client-id` and `CHIO_MCP_AUTH_INTROSPECTION_CLIENT_SECRET` stay: they are the edge's own credentials, not provider identity |
| `serve-http` per-store path flags (`--session-db`, `--receipt-db`, `--revocation-db`, `--authority-db`, `--budget-db` and the others) | `deploy/reference-runtime`, the SDK publication script, example networks | delete for `serve-http`; callers move to `--state-dir` | a second way to place stores; the single-instance lock needs one directory. `chio trust serve` flags are unchanged |

### 2.5 M0 inventory gap decisions

The M0 producer inventory (`docs/superpowers/specs/relying-party-wedge/receipt-producer-inventory.md`, section "Spec gaps found") listed twelve gaps, and the staged verdict-matrix README listed a scenario count mismatch. Each row below is recorded as: Decided 2026-10-17 (coordinator call; founder may override). The sections named in the last column carry the decision in full.

| # | Decision | Where it lands |
|---|---|---|
| G1 | Committed receipts land in one squash-merged PR (M1 item 2). `ChioReceiptBody` and `ToolCallAction` are single structs, so the format change and every producer change together. Inside the PR, commits follow the inventory's commit groups (1 core types and the portable signer, 2 hosted kernel, 3 FFI, WASM and mobile, 4 security, control-plane, HTTP and proxy producers, 5 observability, products, harnesses and fixtures), and each producer's salt-source wiring is its own commit. Intermediate commits need not build; the PR tip is the verified unit, as for the M0 trait collapse. No producer-by-producer PRs follow it. | Sections 13.3, 10.3 |
| G2 | Every signature over bytes Chio defines signs the section 7.0 wrapper. This includes raw `Keypair::sign` and `SigningBackend::sign_bytes` sites, the kernel checkpoint, domain-prefixed messages, digest signatures, challenge signatures and fixed readiness probes. Only external formats whose signing bytes an external standard fixes are exempt, and the exempt set is closed: JWS signing inputs (RFC 7515, including JWTs and SD-JWT), DSSE pre-authentication encoding, Sigstore Rekor entries, and HTTP message signatures (RFC 9421, no site today). A signature over a digest of a Chio object signs the wrapper over that object's canonical body instead. Both readiness probes sign `chio.signer-readiness-probe.v1` over `{"probe": <name>, "schema": "chio.signer-readiness-probe.v1"}`. The inventory's raw-site table resolves every site to an artifact type and id or to an exemption. | Section 7.0; inventory "Signing sites outside the named helpers" |
| G3 | Salt sources follow one rule: a producer draws salts from the `Rng` seam of the process that signs. A std process (hosted kernel, control plane, proxies, product CLIs, exporters) injects the OS RNG; the portable core, WASM, mobile and C ABI rows are unchanged; harness, conformance and fixture producers inject a seeded deterministic `Rng` and their output is fixture material only. Every inventory producer is assigned to one row. A producer that holds only a hash today receives the preimage over its existing channel; no signing path accepts a caller-supplied hash or commitment. A fixture that re-signs a recorded hash is regenerated from its recorded preimage. | Section 7.8 |
| G4 | `HttpReceipt` is a receipt: it carries `receipt_kind`, `boundary_class`, `verdict`, `trust_level`, `redaction_mode` and `content_hash`, and chio-http-core already projects it into a `ChioReceipt` that embeds the whole `HttpReceipt` in `metadata` (`receipt.rs:350`), so one record has two signed forms today. It is deleted. chio-http-core signs `chio.receipt.v1` directly through the shared kernel signer: `tool_server = "http"`, `tool_name = "<METHOD> <route_pattern>"`, the canonical HTTP request (method, route, request id and the request body preimage) is the parameter preimage, and the response status with the response body preimage is the content preimage. `caller_identity_hash` is dropped; the caller is covered by the committed parameters and, from M3, by `authority`. The SDK middleware types (Python, JVM, .NET, `chio-tower`, `api protect`) change in the same PR. No `chio.http-receipt.v1` id exists. The ACP proxy, SCIM deprovision and verified-fix paths follow the G3 preimage rule. | Sections 7.6, 10.3 |
| G5 | Existing signature domain prefixes are dropped. The wrapper's schema id is the only signature domain separation. `canonical_body` is the RFC 8785 canonical JSON of the artifact's signing body: for a NUL-terminated byte prefix before canonical JSON, the JSON after the prefix; for a `{domain, body}` object, `body`; for a `(DOMAIN, signer, body)` tuple, the object `{"body": body, "signer": signer}`, so every non-domain member of today's signed tuple stays signed. Hash and commitment domains that are not signature prefixes (digest, id, key-id, envelope-hash and commitment domains) are unchanged. `scripts/check-domain-separation.py` keeps covering the remaining hash domains. | Section 7.0 |
| G6, G8 | One schema id per signed artifact. The wrapper id is the signed artifact's id, never a payload or body id. A request and its response are two artifacts with two ids: the broker authority RPC uses the registered `chio.broker-authority-request.v1` and `chio.broker-authority-response.v1`, and the control-plane active-response authority uses `chio.active-response-policy-authority-request.v1` and `chio.active-response-policy-authority-response.v1`. Where an artifact carries a `schema` member, it equals its wrapper id, so the shared `chio.broker-authority-rpc.v1` and `chio.active-response-policy-authority.v1` member values are replaced in M1 item 1. The four `SignedKeyLogEvent` authorization roles keep one id, `chio.key-log.event.v1`: each role is checked against a distinct expected key and all four state the same thing (this key approves this exact event body), as today. Security events use `chio.signed-security-event.v1`; the separate `chio.security-event-body.v1` registry row is a payload schema already named as that row's `payloadSchemaFile`, and M0 PR 4 removes it (the schema file stays). | Section 7.0; plan Task 6 |
| G7 | Generic SDK signing takes a schema id. `chio-binding-helpers` `sign_json_str_ed25519` and its FFI, C++, Python and TypeScript wrappers become one wrapped signer `(schema_id, json, seed)` and one verifier `(schema_id, json, public_key, signature)`; an id outside the registry fails. `sign_utf8_message_ed25519` and its wrappers are deleted, because no Chio key signs raw text; its one non-test caller (`sdks/cpp/chio-cpp/src/dpop.cpp:101`) moves to a wrapped artifact in M1 item 1. | Section 7.0, 10.10 |
| G9 | One signed tool manifest. The `chio-core-types` `ToolManifest`, `ToolManifestBody` and `ToolManifest::sign` have no non-test producer outside their own crate and are deleted in M1 item 1. chio-manifest `SignedManifest` (`chio.manifest.v1`) is the only signed manifest. The shared tool types (`ToolDefinition` and the others chio-manifest re-exports) stay in core-types. No `chio.core-tool-manifest.v1` id exists. | Section 10.1 |
| G10 | Chio DPoP proofs use `chio.dpop_proof.v1`. On `main` the registry, schema, kernel, C++ and TypeScript code still carry `chio.dpop_proof.v2` for the durable replay-authority profile. #1489 (parallel lead) is open and requires one activated profile; the removal of `chio.dpop_proof.v2` follows #1489 in the lead's lane, with the surviving profile under `chio.dpop_proof.v1`. M0 does not edit the DPoP rows. | Section 7.0; D17 |
| G11 | Every wrapper id is registered before the wrapper verifies it, and registration lands with the Rust type in M1 item 1, in the same PR as the wrapper. Registering in M0 was rejected: every `registry.json` row needs a hashed `schemaFile`, and a schema under `spec/schemas/chio-wire/v1/` regenerates code in four languages, so M0 would hand-write about sixty schemas for existing types that no test validates against their serialization until M1. M1 item 1 registers the 63 ids that the staged PROTOCOL 4.5 table names and `spec/schemas/registry.json` does not list. The 63 cover the wrapper-table ids, the four root-authority ids (`chio.root-policy.v1`, `chio.idp-key-snapshot.v1`, `chio.revocation-request.v1`, `chio.settlement-closure.v1`) and the raw-site ids; the earlier count of 51 covered only the wrapper table. It also registers the id of every `SignedExportEnvelope<T>` payload type not already in the registry, and adds each id to `KNOWN_SIGNED_ARTIFACT_SCHEMAS`. The wrapper's verification helper refuses any id outside that list. M0 publishes the complete id table in staged PROTOCOL 4.5. | Sections 7.0, 13.2; plan Task 6 |
| G12 | No new error domain. The proposed codes move into existing domains whose descriptions already cover them: exchange failures under `transport` (token endpoint authentication), anchor and root failures under `capability`, root-policy load failures under `policy`, receipt signing and export failures under `attest`. Each code is registered in `spec/errors/registry.yaml` by the M1 PR that first emits it. `CHIO-KERNEL-REVOCATION-STORE` becomes `urn:chio:error:kernel:revocation-store` in M1 item 5. The staged scenarios use the renamed codes. | Verdict-matrix README |
| G13 | Decided 2026-10-17 (coordinator call; founder may override). The content preimage of an output has three forms: canonical JSON for a value, the zero-length byte string for an empty output, and the concatenated lowercase hex SHA-256 of each canonical chunk for a stream (no chunks is empty). The verifier derives the preimage from its own copy of the output, never from an opening's `payload`, so the literal `null` is never a preimage and cannot collide with a salt-only `payload: null` opening. The #1537 empty-output and deny vectors use `null` as the preimage and are regenerated to the zero-length form. | Sections 7.6, 7.7; PROTOCOL section 6 |
| G14 | Decided 2026-10-17 (coordinator call; founder may override). The `receipt_id` in `chio.receipt-disclosure.v1` and the `terminal_receipt_id` in `chio.settlement-closure.v1` are bare lowercase hex, as the PROTOCOL receipt id rule produces. The `rcpt_sha256:` prefix in the earlier examples was wrong. | Sections 7.7, 7.10; PROTOCOL sections 6, 6.7 |
| G15 | Decided 2026-10-17 (coordinator call; founder may override). A verifier rejects an opening document in which the same salt appears for more than one `salt_ref`. The receipt is marked as tampered disclosure. | Section 7.7; PROTOCOL section 6 |
| G16 | Decided 2026-10-17 (coordinator call; founder may override). G11 counts 63 unregistered ids, the number of ids in the staged PROTOCOL 4.5 table that `spec/schemas/registry.json` does not list (wrapper-table, root-authority and raw-site ids), not 51. | Section 2.5 G11; PROTOCOL section 4.5 |
| G17 | Decided 2026-10-17 (coordinator call; founder may override). The enterprise provider registry (`chio.enterprise-providers.v1`, `--enterprise-providers-file`) is kept in `serve-http` and is the one source of provider identity: `provider_id`, kind, issuer, keys (`jwks_url`, or an inline `jwks`), introspection endpoint, audience (`trust_boundary.allowed_audiences`), subject mapping (`principal_source` names one claim; `tenant_id_field` names the tenant claim), trust material reference and enabled state. A root policy rule of a provider-backed kind (`oauth_id_jag`, `entra_jwt`, `entra_agent_id`, `oidc_jwt`, `oauth_introspection`) names `provider_record_id` and pins `provider_identity_digest` over the record's identity projection (`chio.enterprise-provider-identity.v1`, which excludes `enabled`). The rule owns no provider identity member: it holds the anchor kind, scope ceiling and projection, claim match, allowed algorithms, lifetimes and holder classes. Issuer, keys and subject mapping are therefore configured once, and the offline policy key still governs which provider identity a rule trusts. Every exchange, and every admission under a provider-anchored root, loads the registry once per request (bounded, as #1535) and matches against that one version. A missing, disabled or invalid record, a record of the wrong kind, or an identity digest that differs from the rule's denies; an unreadable or invalid registry answers HTTP 503 on the token endpoint and bearer intake and denies admission. There is no cached copy and no fallback. The `serve-http` verification flags and `--auth-jwt-provider-profile` are deleted, as is the record member `provider_profile` (trust-control callers change in the same PR). `entra_jwt` takes its principal from the record's one claim, which keeps one principal namespace per provider; the `oid`, `sub`, `azp`, `appid`, `client_id` fallback is dropped. The tenant claim moves from the rule's `tenant_claim` to the record's `tenant_id_field`. | Sections 2.4, 6.1, 7.2, 7.3, 7.4, 7.12, 8, 9.8, 10, 11, 12 (M1), 13.2 |
| G18 | Decided 2026-10-17 (coordinator call; founder may override). Strict decoding for every signed v1 type this spec adds or changes in place: `root_anchor` and the capability body that carries it, `chio.delegation-context.v1`, `chio.root-policy.v1`, `chio.idp-key-snapshot.v1`, `chio.enterprise-provider-identity.v1`, `chio.capability-presentation.v1`, `chio.receipt-disclosure.v1`, the receipt's commitment, `disclosure`, `authority`, `enforcement` (`pdp_decision`) and `settlement` blocks, the metering and runtime-attestation blocks carried beside them, `chio.settlement-closure.v1` and `chio.revocation-request.v1`. Each rejects an unknown member at every nesting level, even when the signature over the padded body is valid. A tagged union never uses serde internally tagged unit variants, which accept padding such as `{"kind":"x","pad":0}` (fixed for Work frames in #1540); a closed discriminator is a plain string enum member of a closed struct, and a union whose variants carry different members uses closed struct variants or the #1540 lossless round trip (the typed value re-encodes to exactly the input value). `#[serde(flatten)]` is not used in these types, because it disables unknown-member rejection. New tagged-enum Rust types use `chio_security_types::strict_serde` (`lossless_serde!`, #1551) for padding refusal, never a local helper. The capability tree's strict decoding lands in the parallel lead's lane; these types follow the same rule. | Section 7.0; PROTOCOL 4.5; sections 11.1, 11.2, 11.3 |
| G19 | Decided 2026-10-17 (coordinator call; founder may override). A verifier derives the signature algorithm only from the pinned, typed key it verifies against, never from any member of the artifact. The unsigned top-level `algorithm` member (`CapabilityToken.algorithm` and `ChioReceipt.algorithm`, plus the same optional member on the other `chio-core-types` and `chio-credit` envelopes) is deleted in M1 item 1, the wrapper PR, with every caller. After it, an `algorithm` member, added or altered, fails strict decoding (G18) before any verifier is chosen, and no member can change which verifier runs. | Section 7.0; PROTOCOL 4.5; sections 11.1, 11.2, 11.3 |
| Count | `anchored_root` is 24 in M1, as section 11.3 says. The staged corpus gained four scenarios in the gap PR (013 Entra multi-tenant issuer deny, 014 Entra `uti` reuse after root expiry deny, 015 Entra issuer on an `oidc_jwt` rule rejected at load, 016 root signed by a key outside `exchange_keys` deny) and gains eight here (017 provider disabled after the root was issued, 018 provider removed before exchange, 019 registry unreadable at exchange, 020 provider identity changed without a re-signed policy, 021 registry unreadable at admission, 022 padded `root_anchor`, 023 added `algorithm` member, 024 padded root policy rejected at load), for 24, 12 and 12 (48 files). Item 5 then splits `revocation_local` 010 into 010a, 010b and 010c (section 7.11 boundaries), so the staged corpus is 24, 12 and 14 (50 files). | Section 11.3; plan Task 3 |

Size effect: M1 item 1 grows by the raw-site resolution, the id registration with schemas, the binding signer change and the core manifest deletion; M1 item 2 grows by the `HttpReceipt` deletion with its SDK middleware and by the preimage plumbing for hash-relaying producers. G17 to G19 grow item 1 by the `algorithm` member deletion and its negatives (+1 to +2), item 3 by strict decoding of the new types with padding negatives (+1), item 4 by the provider identity projection, per-request registry reads at exchange and admission, the record and flag changes and the registry scenarios (+2 to +3), and item 6 by the provider identity export role (+0 to +1). M0 is unchanged. Section 13.2 carries the new sizes.

## 3. Goals, non-goals, anti-goals

### 3.1 Goals

1. **G1 External roots.** ID-JAG and ordinary Entra tokens (M1) and Entra Agent ID tokens (M2) become verified delegation roots at the MCP edge, recorded in every capability and receipt derived from them.
2. **G2 Key custody (M2).** Receipts and exchange-issued roots can be signed by an AWS KMS key the process never holds.
3. **G3 Privacy by default.** Every Chio receipt carries salted commitments to arguments and results. Plaintext appears in a receipt only where the signed root policy authorizes it for that tool and field (M2).
4. **G4 Interop (M2).** Incumbent gateways call Chio through an AuthZEN 1.0 decision endpoint. SIEMs ingest OCSF 1.9 API Activity events carrying the delegation and record-integrity objects.
5. **G5 Portable multi-hop chains (M2).** A chain of any depth rooted in an exchange-issued root verifies offline from a bundle.
6. **G6 Paid tools (M3).** The edge answers an unpaid call to a priced tool with an x402 payment challenge and binds the settlement into the receipt.
7. **G7 Counterparty verification.** A provider exports a receipt bundle for one tenant; the tenant verifies it offline with `chio-verify`.

### 3.2 Non-goals

- **No runtime.** Chio does not host agents, sandboxes, workflows or tool servers.
- **No custody.** No wallet keys, no funds, no stored payment instruments, no escrow.
- **No compute.** No metered compute resale.
- **No multi-instance deployment** of one provider's edge (D4).
- No leases (`chio.lease.v1`), no revocation-head bitstrings, no durable stop. KERN-1 stays on its own track.
- No hierarchical spend lines, allocation certificates or `partition_escrowed` budgets.
- No self-anchored roots (Web Bot Auth, X.509-SVID, WIMSE) and no anchor verification inside the portable `no_std` core.
- No SCITT registration. Checkpoints and existing witness lanes are unchanged.
- No mainnet settlement on any chain.
- No Backbay-hosted exchange or receipt service.
- No Entra Continuous Access Evaluation or OpenID Shared Signals intake. CAE is unscheduled roadmap and not before M3 completes (F12).

### 3.3 Anti-goals

These are outcomes the design must actively prevent.

- **IdP as attenuation authority.** An IdP claim may narrow a ceiling. It must never widen one, and it is never consulted after the root.
- **Bearer pass-through.** No IdP token, ID-JAG or Entra token reaches an upstream tool server, a receipt, a log line or an OCSF event. A retained ID-JAG (D7) lives only in the evidence store and in auditor bundles.
- **Unauthorized plaintext.** No code path writes tool arguments, results, principals or tenant ids into a signed receipt, guard evidence, metadata or OCSF output unless the signed root policy authorizes that tool and field.
- **A second signing identity on failure.** A KMS outage never falls back to a local key.
- **Overclaimed enforcement.** A `pdp_decision` receipt never renders as Chio-enforced authorization in any verifier, SIEM projection or copy.
- **Compat paths.** Every in-place v1 change updates all callers and deletes the old shape in the same PR.

## 4. User stories

### 4.1 Tool provider (platform or security engineer at the company running the MCP server or API)

- P1. As the provider, I configure my callers' Okta and Entra tenants (M1; Entra Agent ID from M2) once in a signed root policy, and any agent from those tenants can call my tools under a ceiling I set, without per-agent provisioning.
- P2. As the provider, I see for every call which IdP authenticated which principal, under which root policy, through which delegation chain, and what my server returned, in a record I can show my auditor.
- P3. (M2) As the provider, my receipt signing key lives in AWS KMS, so a compromise of the edge host does not let the attacker forge past receipts.
- P4. As the provider, my receipt store holds no customer plaintext unless my signed policy says so for a named tool and field.
- P5. As the provider, I revoke a capability, a principal, a policy rule or a whole tenant, and the next call under it denies.
- P6. (M2) As the provider, my existing API gateway asks Chio for a decision through AuthZEN and I keep my gateway.
- P7. (M2) As the provider, my SIEM receives OCSF events without plaintext arguments.
- P8. (M3) As the provider, I price a tool per call and Chio refuses to run it until an x402 payment settles to my address.
- P9. As the provider, I export a bundle for one tenant containing only that tenant's receipts.
- P10. As the provider, for development, tests and conformance I start `serve-http` with a static `--auth-token` that maps to one principal I name in the root policy, and the receipts say that identity is operator-attested.

### 4.2 Calling agent's operator (the company whose agents call the provider)

- C1. As the caller, my agents use our Okta or Entra identity (M1; Entra Agent ID from M2). I do not create accounts at every provider.
- C2. (M2) As the caller, my orchestrator receives a capability from the provider and delegates a narrower one to a sub-agent, and the provider enforces the narrower one.
- C3. (M2) As the caller, each tool response carries the signed receipt and the opening material for my own call, so I keep my copy without asking the provider later.
- C4. As the caller, when the provider bills me or disputes a call, I verify the provider's bundle offline and see whether each call was authorized, which of my principals it was attributed to, and whether the result matches what I received.
- C5. As the caller, I disable a principal in Okta and the provider stops honoring capabilities rooted in it within 300 s plus the configured clock skew. For Entra principals I know the bound is the token's expiry.
- C6. (M2) As the caller, I revoke a capability I delegated to a sub-agent by sending the provider a signed revocation request.

### 4.3 Auditor (internal audit at either party, or an external assessor)

- A1. As the auditor, I verify a bundle on an air-gapped machine with an Apache-2.0 tool and a trust file I control.
- A2. As the auditor, I get a per-column report (identity root, delegation chain, decision, content, settlement) with an evidence class per column.
- A3. As the auditor, I can be given hash-only bundles that prove integrity without exposing arguments, and I cannot recover low-entropy arguments from them.
- A4. (M2) As the auditor, I can distinguish calls Chio enforced from decisions Chio made for another enforcement point.
- A5. (M2) As the auditor, I can see from the signed policy that every plaintext field in a receipt was authorized.

## 5. Today: verified code facts that shape the design

Line numbers are at `d0482967b8`.

| # | Fact | Label | Source |
|---|---|---|---|
| T1 | Local AS token exchange accepts only `subject_token_type = urn:ietf:params:oauth:token-type:access_token`, and `validate_subject_token` accepts only EdDSA tokens signed by the local AS's own key with `iss` equal to itself. It exchanges self-issued tokens only. | shipped | `crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/local_server.rs:444-545` |
| T2 | AS metadata advertises `authorization_code` and `token-exchange`. No `jwt-bearer` grant exists. | shipped | `.../remote_mcp/http_service_auth.rs:338-342`; `local_server.rs:301-317` |
| T3 | Bearer JWT verification supports EdDSA, RS256/384/512, PS256/384/512, ES256, ES384 and resolves RSA, P-256, P-384 and OKP JWKs. | shipped (edge qualified) | `.../remote_mcp/session_identity.rs:8-44,244-317` |
| T4 | The JWKS is fetched once at startup. No refresh on unknown `kid`. | shipped | `.../remote_mcp/http_service.rs:47`; `session_identity.rs:170-208,319-372` |
| T5 | `JwtHeader` parses only `alg` and `kid`. There is no `typ` check, so an ID-JAG cannot be told apart from an access token by header. | shipped | `.../remote_mcp/session_core.rs:1008-1012` |
| T6 | Session capabilities are issued by the edge's capability authority (local or pinned remote trust-control) after bearer authentication. Nothing records the IdP assertion in the capability. | shipped | `.../remote_mcp/session_core/factory.rs:203-261` |
| T7 | With durable admission off, the hosted edge kernel signs with `Keypair::generate()`, an ephemeral key. | shipped | `factory.rs:171-185` |
| T8 | Federated subject keys are derived from the authority seed per principal (`derive_federated_agent_keypair`, `derive_enterprise_subject_key`). | shipped | `session_identity.rs:474-484,681-696` |
| T9 | `SigningBackend` is synchronous and dyn-compatible. `algorithm()` and `public_key()` are infallible; `current_public_key()` is fallible with an infallible default. `sign_bytes_with_identity` and `sign_bytes_for_identity` return a `SigningOutcome` (key, algorithm, signature) and the default implementations verify the signature locally. Since #1513 the core-types artifact helpers stamp signer identity from the `SigningOutcome`. `sign_canonical_bytes` signs the canonical body bytes directly. `chio-signing-remote` implements the trait for an HTTP signer and Vault Transit over blocking `ureq`, Ed25519 only. | shipped | `crates/core/chio-core-types/src/crypto.rs:896-1020`; `src/signer_binding.rs`; `crates/trust/chio-signing-remote/src/lib.rs` |
| T10 | P-256 and P-384 signing and verification require the `fips` feature (aws-lc-rs, std only). Without it, `verify_ecdsa_p256` returns `false`, so a P-256 signature fails verification in every default build. | shipped | `crypto.rs:1245-1270`; `crates/core/chio-core-types/Cargo.toml` |
| T11 | Kernel construction takes a `Keypair` and wraps it in `Ed25519Backend` (or hybrid). No path passes a remote `SigningBackend` into receipt signing. | shipped | `crates/kernel/chio-kernel/src/receipt_support/signing.rs:429-470`; `crates/platform/chio-control-plane/src/lib.rs:114-120` |
| T12 | Receipts sign the canonical JSON of `ChioReceiptSigningBody { id, body, bbs_signature? }` directly, so the signing preimage grows with the body. `bbs_signature` is a member of that body. | shipped | PROTOCOL 6 "Receipt Identity And DAG"; `receipt/signing.rs` |
| T13 | `ToolCallAction` carries `parameters` in clear plus an unsalted SHA-256 `parameter_hash`. `content_hash` is an unsalted SHA-256 of the output preimage. Both are brute-forceable for low-entropy values. | shipped | `crates/core/chio-core-types/src/receipt/decision.rs:35-59`; `receipt/body.rs` |
| T14 | `sign_receipt_relaying_trusted_body` is the FFI and WASM relay seam. It trusts a caller-asserted `content_hash` because it does not hold the content preimage. | shipped | PROTOCOL 6 "WYSIWYS Signing Invariant" |
| T15 | Closed enums: `ReceiptKind {mediated_decision, trace_observation, advisory_evaluation}`, `BoundaryClass {prevent, detect_only, advisory_only, cannot_see}`, `TrustLevel {mediated, verified, advisory}`, `RedactionMode {none, summary, redacted}`. | shipped | `receipt/kinds.rs:11-135` |
| T16 | `verify_capability_full_with_evidence` in `chio-kernel-core` verifies signed ancestor tokens in root-to-parent order against a `TrustRootResolver`. Hosted kernels feed it from receipt-store snapshots. No portable carrier or CLI path feeds it offline. The approved wording remains "single-hop portable, deeper chains hosted". | shipped | `crates/kernel/chio-kernel-core/src/capability_verify.rs:499-530`; PROTOCOL 5 "Chain-Binding Rule (W1.1)" |
| T17 | Without an installed `RevocationView`, the kernel checks the per-row `RevocationStore` and refuses an ephemeral store unless explicitly allowed; `serve-http` backs it with SQLite through `revocation_db_path`. An installed view adds a staleness bound. `serve-http` already exposes `/admin/revocations`. | shipped | `crates/kernel/chio-kernel/src/kernel/construction.rs:583-598`; `chio-kernel-core/src/revocation_view.rs:120-135`; `session_core.rs:92,216` |
| T18 | OCSF projection targets schema 1.3.0, class 6003 API Activity, activity 99 "Tool Call", with source data under `unmapped.chio`. | shipped | `crates/observability/chio-siem/src/ocsf.rs:1-104` |
| T19 | `chio api protect` mounts the mediated route (`/v1/evaluate`, `/v1/caller/start`, `/v1/caller/report`, `/v1/reconcile`) and mints unanchored capabilities through `/v1/capabilities/mint`. | shipped | `crates/products/chio-api-protect/src/proxy/router.rs:40-95` |
| T20 | `X402PaymentAdapter` is a custom prepaid POST client with serde aliases for its response id. It does not speak the x402 facilitator `/verify` and `/settle` API, and no code emits or parses a 402 challenge. | shipped | `crates/kernel/chio-kernel/src/payment.rs:108-113,489-500` |
| T21 | `chio evidence verify` is implemented in `chio-control-plane` (`evidence_export.rs`, `evidence_export/verification.rs`), which links the whole control plane. The export manifest is `chio.evidence_export_manifest.v1`. | shipped | `crates/products/chio-cli/src/cli/dispatch/receipt_evidence.rs:160-205`; `crates/platform/chio-control-plane/src/evidence_export/` |
| T22 | PROTOCOL 8.2: hosted OAuth authorization-server product work is blocked until an OAuth AS ADR is accepted. No such ADR is in `docs/adr/`. | design gap | `spec/PROTOCOL.md` 8.2; `docs/adr/` listing |
| T23 | MCP confirmation profiles are closed. RFC 9449 `jkt` is rejected. Remote sessions use `cnf.chioSenderKey` as the capability subject. | shipped | PROTOCOL "Inbound sender authority profile" |
| T24 | Verdict-matrix corpus has 72 scenarios with a pinned index hash. `rust-kernel` is the required driver. | shipped | `crates/tooling/chio-conformance/verdict_matrix/manifest.toml` |
| T25 | The clock gate covers `chio-mcp-remote`, `chio-mcp-edge`, `crates/kernel/`, `crates/guards/`, `crates/security/`, the control plane and `chio-store-sqlite` among fixed roots. It does not cover `crates/trust/` or `crates/core/`. | shipped | `scripts/check-security-clocks.py:28-48` |
| T26 | `serve-http` auth modes are `StaticBearer` (a shared `--auth-token` secret with no principal), `JwtBearer` and `IntrospectionBearer`, plus the local AS. The local AS client registry holds only `client_id` and one redirect URI and advertises `token_endpoint_auth_methods_supported: ["none"]`: every client is public. Since #1535 the enterprise provider registry file is loaded once per JWT and introspection bearer request: a disabled or removed provider no longer matches, the matched record supplies `provider_record_id`, subject mapping and trust material reference, and an unreadable or invalid registry answers HTTP 503. Token verification itself is still configured by the `--auth-jwt-*` and `--auth-introspection-url` flags. | shipped | `session_core.rs:151-154,179,808-818`; `http_service_auth.rs:342,676-740`; `oauth/bearer_auth.rs:556-566,840-850`; `session_identity.rs:456-566` (at `d78dfef2dc`) |
| T27 | `ChioReceiptBody` carries an optional plaintext `tenant_id`. | shipped | `receipt/body.rs:93` |
| T28 | The MCP edge reads Chio `_meta` members from a closed list of `chio`-prefixed names (#1503). `chioCapability` and `chioReceipt` are not on it. | shipped | `crates/protocol/chio-mcp-edge/src/runtime/protocol/parsing.rs` |
| T29 | `CapabilityToken.algorithm` and `ChioReceipt.algorithm` are optional members outside the signing body, documented as informational; verification dispatches off the self-describing key and signature encodings. Twelve such optional `algorithm` members exist across `chio-core-types` and `chio-credit`. | shipped | `crates/core/chio-core-types/src/capability/token.rs:138-140`; `receipt/body.rs:104-107` (at `d78dfef2dc`) |
| T30 | serde's `deny_unknown_fields` does not apply to unit variants of internally tagged enums, so `{"kind":"x","pad":0}` decodes. #1540 closed this for Work frames with a lossless round trip; the capability tree's strict decoding is in the parallel lead's lane. | shipped | #1540; `crates/core/chio-core-types` |

## 6. Architecture and data flow

### 6.1 Components in the provider's deployment

```text
               provider's deployment: ONE instance (D4), customer-hosted (F1)
 +-----------------------------------------------------------------------------+
 |  chio mcp serve-http                                                        |
 |                                                                             |
 |  [local AS]  /oauth/token  (confidential client authentication)            |
 |     jwt-bearer grant (ID-JAG)                                               |
 |     token-exchange (ID-JAG, Entra, local AS re-exchange; capability out)    |
 |     authorization_code (local AS users)                                     |
 |                                  |                                          |
 |  [bearer intake]  static bearer, OIDC JWT, introspection, Entra (M1)        |
 |                                  v                                          |
 |  [provider registry]  read once per request: issuer, keys, subject map,     |
 |     enabled; unreadable -> 503                                              |
 |  [root exchange]  verify assertion -> one root policy rule -> mint root     |
 |     signs with EXCHANGE key (seed file or trust-control; KMS from M2)       |
 |                                  |                                          |
 |                                  v                                          |
 |  [MCP edge + kernel]  verify chain (anchored trust root), provider record   |
 |     check, revocation read in the admission transaction, guards,           |
 |     x402 challenge (M3), dispatch                                           |
 |     signs committed receipts with KERNEL key (seed file in M1; KMS from M2) |
 |                                  |                                          |
 |  [state dir, SQLite, exclusive lock] receipts, disclosure openings          |
 |     (erasable), revocations, replay keys, roots, presentations,             |
 |     key snapshots, tenant and subject tags, admission, budgets              |
 |                                                                             |
 |  [AuthZEN]  /access/v1/* for listed PEPs (M2)                               |
 +--------------------------|--------------------------------------------------+
                            |  wrapped MCP server (unchanged)
                            v
                      provider's tool server

 chio api protect  (HTTP APIs; committed receipts from M1, anchored roots and x402 in M3)
 chio-verify       (tenant's or auditor's machine, offline)
 AWS KMS           (M2: two keys, exchange role and kernel role)
 Okta / Entra      (JWKS fetched online by the exchange only)
 x402 facilitator  (third party, /verify and /settle, M3)
```

Deployment limit (D4): one `serve-http` process per provider state directory.

- `--state-dir` replaces the per-store database path flags (`receipt_db_path`, `revocation_db_path`, `authority_db_path`, `budget_db_path` and the other per-store paths in `RemoteServeHttpConfig`). Every SQLite file the process writes lives under it. There is no second way to place a store.
- At startup, before opening any store, the process takes an OS advisory exclusive lock (`flock`) on `<state-dir>/LOCK` and holds it for its lifetime. If the lock is held, startup refuses. The OS releases the lock when the process dies, so a crash never leaves a stale lock.
- The state directory must be on a local filesystem. Startup refuses a network filesystem where advisory locks are unreliable (the builder pins the detection method per platform).
- Rolling deployments that start the new process before the old one exits fail by design. Deploy with stop-then-start.
- Restoring a state-directory backup rewinds the replay store. An ID-JAG used after the backup and still inside its lifetime (at most 300 s by default) could be exchanged again. The operations guide says to wait `max_assertion_lifetime_secs + max_clock_skew_secs` after a restore before serving.

Three provider keys and one local AS key are distinct and pinned separately:

- **exchange key**: signs root capabilities and IdP key snapshots. Pinned in verifier trust files.
- **kernel key**: signs receipts, settlement closures and export commitments. Pinned in verifier trust files.
- **policy key**: signs the root policy. Pinned in the `serve-http` configuration and in verifier trust files. Intended to be held offline.
- **local AS key**: signs local AS JWS access tokens. Never pinned by verifiers.

No two of them may be the same key (startup refusal, section 8.3).

Provider identity lives in one place, the enterprise provider registry file (`--enterprise-providers-file`, `chio.enterprise-providers.v1`), which the existing provider-admin writer updates under its lock with durable bounded persistence (G17). Root policy rules reference records by id and pin their identity digest (section 7.4). `serve-http` reads the file once per exchange and once per admission under a provider-anchored root, so enabling, disabling or removing a provider takes effect at the next request. A change to a record's identity projection takes effect only together with a root policy re-signed by the offline policy key.

### 6.2 Flow A: ID-JAG (Okta Cross App Access, MCP Enterprise-Managed Authorization), M1

Pin at build start: MCP ext-auth `specification/stable/enterprise-managed-authorization`, the IETF Identity Assertion JWT Authorization Grant draft revision it references, and the token endpoint client authentication method the stable profile requires.

1. The MCP client obtains an ID-JAG from the enterprise IdP through RFC 8693 token exchange at the IdP. The ID-JAG `aud` is the provider's AS issuer (the Chio local AS).
2. The client calls the Chio local AS token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and `assertion=<ID-JAG>`, and authenticates as a confidential client with `private_key_jwt` (RFC 7523 section 2.2). The client registry (#1380) gains a per-client public JWK and `token_endpoint_auth_method`. Public clients (`none`) cannot use the `jwt-bearer` or `token-exchange` grants. The client assertion has `aud` equal to the token endpoint URL, a lifetime of at most 60 s, and a `jti` recorded in the replay store. If the stable profile mandates a method other than `private_key_jwt`, the builder adds exactly that method and records it in the ADR.
3. The exchange loads the provider registry once for the request, verifies the ID-JAG against the matched rule's provider record (section 8.1), records its replay key, matches exactly one root policy rule, computes the effective root scope, mints a root `chio.capability.v1` with `root_anchor`, writes the `chio.delegation-context.v1`, writes the tenant and subject tags (section 7.12), and signs the root with the exchange key.
4. Root lifetime: `expires_at = min(now + capability_ttl_secs, assertion exp)`. If the result is not after `now`, the exchange denies. The rule's `max_assertion_lifetime_secs` (default 300) bounds `exp - iat` of accepted ID-JAGs. A longer-lived ID-JAG denies.
5. The AS returns an access token (local AS EdDSA JWT, `exp` equal to the root's `expires_at`, claim `chio_root` = root capability id). The existing local AS DPoP and mTLS sender constraints apply to it unchanged. No refresh token is issued (consistent with the existing refusal of `offline_access`, #1358).
6. The client calls `tools/call` with the access token. The edge resolves `chio_root` to the stored root and evaluates the call. For clients without a Chio sender key, the root is session-held (section 6.5).
7. The kernel signs the committed terminal receipt with the kernel key. From M2 the response carries the receipt and the caller's openings in `_meta.chioReceipt` (D11).
8. When the root expires, the client obtains a fresh ID-JAG and repeats step 2.

Kill latency (D5): each ID-JAG is single-use and yields one root that ends at or before the ID-JAG's own `exp`. Once the IdP stops issuing ID-JAGs for a principal, no root for that principal outlives `max_assertion_lifetime_secs` (300 s default) plus the clock offset between the IdP and the provider, which the `iat` check bounds by `max_clock_skew_secs`. Provider-side revocation (section 7.11) takes effect for every call admitted after it commits.

### 6.3 Flow B: Entra (`entra_jwt` in M1, `entra_agent_id` in M2)

Pin at build start: Microsoft identity platform access token reference (token version, per-tenant issuer format, `oid`, `azp`, `appid`, `tid` and `uti` claims) for M1, and the Microsoft Learn Entra Agent ID token reference (claims that identify an agent identity and its blueprint) for M2.

Ordinary Entra application and workload tokens take the `entra_jwt` kind from M1. From M2, a token carrying the agent-identity discriminator claim is matched only against `entra_agent_id` rules, and a token without it only against `entra_jwt` rules, so exactly-one-rule matching holds with both kinds configured. Both kinds follow the flow and rules below.

Two entry points produce the same anchored root:

- **Bearer at the edge.** The agent presents an Entra access token (`aud` = the provider's app ID URI) on MCP requests. The edge looks up the root by the digest of the exact token bytes. On first sight it performs the exchange internally (flow A steps 3-4) and stores the token-digest-to-root mapping. Later requests carrying the same token, in any session, use that root until it expires. The Entra token itself is never stored.
- **Explicit RFC 8693.** A Chio-aware caller posts the Entra token as `subject_token` with `subject_token_type=urn:ietf:params:oauth:token-type:jwt` and `requested_token_type=urn:chio:params:oauth:token-type:capability-v1`, authenticating as a confidential client (flow A step 2). The response's `access_token` member holds the canonical JSON root capability, `issued_token_type` echoes the Chio type, and `token_type` is `N_A` (RFC 8693 section 2.2.1).

Rules (D5):

- One root per Entra token, keyed by `(issuer, uti)`. A different token presenting an already-bound `uti` denies. A second explicit exchange of the same token denies.
- Root lifetime is `min(capability_ttl_secs, token exp - now)`, so at most 300 s by default.
- After the root expires, requests carrying the same token get HTTP 401 with RFC 6750 `error="invalid_token"`, which prompts token libraries to acquire a new token.

Kill latency: Chio does not observe Entra revocation in v1. A caller that already holds several unexchanged Entra tokens can exchange each once until it expires. The claim is therefore that IdP revocation of an Entra principal takes effect at the expiry of tokens issued before it, about one hour for typical Entra access tokens. Provider-side revocation of the principal (section 7.11) takes effect for every call admitted after it commits.

An `oidc_jwt` rule whose provider record has a Microsoft Entra issuer rejects at policy load (D14), so every Entra token is held to these rules. The principal is the claim the record's `subject_mapping.principal_source` names (`oid` for Entra records, G17); a token without it denies.

### 6.4 Flow C: multi-hop delegation (G5, M2)

1. A Chio-aware orchestrator obtains its root through RFC 8693 with `requested_token_type=urn:chio:params:oauth:token-type:capability-v1` (ID-JAG input uses `subject_token_type=urn:ietf:params:oauth:token-type:id-jag`), bound to its `cnf.chioSenderKey`.
2. It delegates a narrower capability to a sub-agent with an ordinary `DelegationLink` (existing attenuation, W1.1 and W1.2 unchanged).
3. The sub-agent calls `tools/call` with `_meta.chioCapability` holding `chio.capability-presentation.v1` (leaf plus signed ancestors, section 7.5) and `_meta.chioDpopProof` signed by the leaf subject.
4. The edge verifies the chain with `verify_capability_full_with_evidence` and an `AnchoredTrustRoot` resolver (section 10.2), and checks revocation for every token in the chain. The receipt records `chain_digest` and `chain_depth`, and the presentation is retained for export.
5. The exported bundle contains the presentation, so `chio-verify` re-runs the same pure verification offline.

In M1, presented chains are limited to depth 0 (the root itself, caller-held or session-held). Depth one and deeper arrive in M2 with the portable chain work.

### 6.5 Session-held versus caller-held capabilities

| Caller kind | Capability subject | Holder | DPoP-required grants |
|---|---|---|---|
| MCP client without a Chio sender key (most third-party clients) | fresh per-exchange Ed25519 public key; the private half is discarded at mint | edge, bound to the access token or bearer token that produced the root | unavailable; the exchange denies if the matched rule's ceiling includes them for this holder class |
| Chio-aware client with `cnf.chioSenderKey` | the sender key | caller | available |

A session-held root is a bearer capability whose bearer is the edge on behalf of whoever presents the token that produced it. The receipt says so through `authority.holder = "edge_session"`. Because its subject private key is discarded, a session-held root can never sign a delegation or a DPoP proof. This replaces the seed-derived subject keys (T8) for every deployment (D1).

### 6.6 Flow D: AuthZEN PDP (M2, `serve-http`)

An incumbent PEP (API gateway, AgentCore interceptor, APIM policy) posts an AuthZEN evaluation to `serve-http` (D9). Chio verifies the presented capability chain, checks revocation, runs guards, signs a `pdp_decision` receipt and returns `decision` plus the signed receipt. Chio does not see the tool's execution. Requests whose grant requires a budget hold, a payment or an output check are denied in PDP mode with `urn:chio:error:pdp-requires-mediation`. Details in section 7.9.

### 6.7 Flow E: x402 paid tool (M3, `serve-http` and `api protect`)

Pin at build start: x402 Foundation specification (`x402-foundation/x402`, `specs/`), including the HTTP transport, the MCP transport, the `exact` scheme, and the facilitator `/verify` and `/settle` request and response schemas.

1. The caller invokes a priced tool without payment.
2. The edge verifies the capability first. If the price exceeds the grant's `max_cost_per_invocation` or the remaining `max_total_cost`, or the cap's asset differs from the price's asset (D13), the edge denies with a signed deny receipt. It does not issue a challenge it would refuse to honor.
3. Otherwise the edge answers with the x402 payment-required response for the transport (HTTP 402 with `PAYMENT-REQUIRED` on `api protect`, or the MCP transport's equivalent on `serve-http`) carrying `accepts` built from the tool's signed manifest price. The challenge is not a receipt.
4. The caller retries with a payment payload. The edge places the existing durable budget hold, calls the facilitator `/verify` then `/settle` (`exact` scheme, settle before execute, the existing `MustPrepay` semantics), and only on a settled response mints the execution nonce and dispatches.
5. The terminal receipt carries the `settlement` block with the decoded settlement response digest and transaction reference. Settlement is inline, so no closure exists.
6. If `/settle` times out or returns an indeterminate state, the call does not execute, the hold enters `outcome_unknown`, the terminal receipt records `settlement.state = "authorized_pending"`, and exactly one `chio.settlement-closure.v1` is emitted when reconciliation resolves it (F4).
7. x402 has no refund protocol. A tool failure after settlement is recorded as settled plus the tool's error outcome. Refunds are out of scope.

## 7. Wire formats (v1, no compat)

All signed bodies use RFC 8785 canonical JSON and the signing wrapper in section 7.0. Every new signed schema id is added to `spec/schemas/registry.json` and `KNOWN_SIGNED_ARTIFACT_SCHEMAS` (`crates/core/chio-core-types/src/signed_artifact.rs`). Existing v1 artifacts change in place; there is no v2. Amounts are integer minor units encoded as decimal strings. Timestamps are Unix seconds. Digests are `sha256:<64 lowercase hex>`. Domain-separation prefixes end in a NUL byte. Every string that feeds a NUL-delimited hash or HMAC input (issuers, subjects, tenant values, claim names) is rejected at intake if it contains a NUL character.

### 7.0 Signing wrapper (protocol-wide, D6, M0 contract, M1 code)

Every Chio signature over bytes Chio defines (capabilities, delegation links, Chio DPoP proofs, receipts, closures, root policies, snapshots, checkpoints, export commitments, readiness probes, challenges and every other registered signed artifact) signs this 88-byte wrapper instead of the body (G2):

```text
wrapper = "chio.signing-wrapper.v1" || 0x00          (24 bytes)
       || SHA-256(utf8(schema_id))                     (32 bytes)
       || SHA-256(canonical_body)                      (32 bytes)
```

What is signed and why:

- `schema_id` is the signed artifact's registered schema id (for receipts `chio.receipt.v1`, for capabilities `chio.capability.v1`), never a payload or body id. Each signed artifact has exactly one id, and a request and its response are two artifacts (G6, G8). Binding it prevents a signature over one artifact type from verifying as another. A verifier takes `schema_id` from its verification context (the artifact type it expects at that call site), never from a member of the artifact being verified.
- `canonical_body` is the RFC 8785 canonical JSON of the artifact's signing body. For receipts that is the canonical `ChioReceiptSigningBody { id, body, bbs_signature? }`, so BBS signature material stays covered by the authoritative signature through this hash. Existing signature domain prefixes are dropped, because the schema id replaces them (G5): after a NUL-terminated byte prefix the body is the canonical JSON that followed it; for a `{domain, body}` object it is `body`; for a `(DOMAIN, signer, body)` tuple it is `{"body": body, "signer": signer}`. A signature over a digest of a Chio object signs the wrapper over the object's canonical body instead. Hash and commitment domains that are not signature prefixes are unchanged.
- Domain separation: no Chio key signs any message other than wrapper bytes, except the local AS key, which signs JWS signing inputs, and keys used only for the exempt formats below. A JWS signing input is base64url text plus `.` and never contains `0x00`, while byte 23 of every wrapper is `0x00`, so the two message spaces are disjoint. The local AS key is still required to differ from every wrapper-signing key (section 6.1).
- Algorithm binding: every pinned key admits exactly one signature algorithm, derived from its self-describing encoding. A signature whose prefix does not match the pinned key's algorithm rejects before any cryptographic check. A verifier holding a pinned hybrid key rejects a bare classical signature, so stripping the post-quantum half yields nothing.
- Algorithm selection (G19): a verifier takes the algorithm only from the pinned, typed key it verifies against, never from any member of the artifact being verified, signed or unsigned. The unsigned top-level `algorithm` member is deleted from `CapabilityToken`, `ChioReceipt` and every other envelope that carries one, in M1 item 1, with every caller. An artifact with an `algorithm` member, added or altered, fails strict decoding before a verifier is chosen.
- Strict decoding (G18): every signed v1 type this spec adds or changes in place rejects an unknown member at every nesting level, even when the signature over the padded body verifies. Tagged unions never use serde internally tagged unit variants; a closed discriminator is a string enum member of a closed struct, and a union whose variants carry different members uses closed struct variants or a lossless round trip (the typed value re-encodes to exactly the input value, as #1540 does for Work frames). `#[serde(flatten)]` is not used in these types. Duplicate member names reject, as today. Members whose value is caller data by definition (an opening's `payload`, `parameters_inline`, `result_inline`, `metadata`) are opaque values; the rule covers every Chio-defined object around them. The SDK verifiers apply the same rule.
- Algorithms: Ed25519 signs the wrapper bytes. ML-DSA-65 signs the wrapper bytes with an empty FIPS 204 context string. P-256 and P-384 sign the wrapper with ECDSA over SHA-256 or SHA-384 of the wrapper, so a KMS can be sent the digest (`MessageType=DIGEST`). Hybrid signatures sign the same 88 bytes with both halves.
- Hash choice: both inner hashes are SHA-256, which caps every signature's collision resistance at 128 bits, including P-384 and ML-DSA-65. This is accepted for v1. Changing the hash or the layout requires a new prefix string and a PROTOCOL change.
- Signature encodings are unchanged (bare 128-hex Ed25519, `p256:<DER hex>`, `p384:<DER hex>`, hybrid form).
- Exempt formats (closed list, G2): JWS signing inputs (RFC 7515, including local AS tokens, JWTs and SD-JWT), DSSE pre-authentication encoding, Sigstore Rekor entries and HTTP message signatures (RFC 9421). Their signing bytes are fixed by the external standard and they do not use the wrapper. Every other signing site does.
- Generic SDK signing (`chio-binding-helpers` and its FFI and language wrappers) takes the schema id as an argument and rejects an unregistered id. No API signs raw caller text (G7).
- Every wrapper id is in `spec/schemas/registry.json` and `KNOWN_SIGNED_ARTIFACT_SCHEMAS` before the wrapper signs or verifies it; the verification helper refuses any other id (G11).
- One signing helper (`sign_wrapped(schema_id, canonical)` on the collapsed `SigningBackend`, returning a `SigningOutcome`) and one verification helper implement the wrapper in `chio-core-types`. `sign_canonical_bytes` is deleted in the same PR. No path signs bodies directly after the change.

Effect: every signing preimage is 88 bytes, so the AWS KMS 4096-byte raw-message limit for Ed25519 no longer constrains any artifact.

### 7.1 `chio.capability.v1` (in place): `root_anchor`

New signed member in `CapabilityTokenBody` (`crates/core/chio-core-types/src/capability/token.rs`):

```json
"root_anchor": {
  "kind": "oauth_id_jag",
  "context_digest": "sha256:7d1e...",
  "root_policy_digest": "sha256:aa90...",
  "anchored_at": 1792234795,
  "assertion_exp": 1792235090
}
```

Rules:

- `root_anchor` is required on every capability admitted by `serve-http` (from M1) and by `api protect` (from M3). A root without it is rejected (F3, D1).
- `kind` is a closed enum (section 7.2). Unknown kinds reject at decode. An unknown member in `root_anchor`, or anywhere in the capability body, rejects at decode (G18).
- A delegated token copies `root_anchor` byte for byte from its root. Any difference denies.
- A root's `expires_at` must not exceed `assertion_exp`. Verifiers check this offline.
- `context_digest` = SHA-256 over `chio.delegation-context.v1\0 || canonical_json(context)`.
- `root_policy_digest` = SHA-256 over `chio.root-policy.v1\0 || canonical_json(policy signing body)`.
- Binding to the delegation context, checked at admission and offline: `assertion_exp` equals `anchor.token_exp`; `anchored_at` equals `exchange.exchanged_at`; the root's issuer key equals `exchange.exchange_key`; the root's scope hash equals `effective_root_scope_hash`; the root's subject is consistent with `exchange.holder` (a `caller` root's subject is the sender key; an `edge_session` root has no `cnf.chioSenderKey`).
- For kinds without an external assertion lifetime (`chio_local_as`, `chio_operator_key`, `operator_static_bearer`), `assertion_exp` equals the local token's, admin request's or minted root's own expiry.

### 7.2 Anchor kinds (closed, v1)

All v1 kinds are exchange kinds (F3). There is no `class` member. Every `serve-http` authentication method kept under D1 and F14 maps to exactly one kind (section 2.4). The provider-backed kinds (`oauth_id_jag`, `entra_jwt`, `entra_agent_id`, `oidc_jwt`, `oauth_introspection`) verify against the provider record their rule references (G17, section 7.4). `--auth-jwt-provider-profile` and the provider verification flags are deleted in M1; the rule's `anchor_kind` and the provider record replace them.

| `kind` | Milestone | Accepted input | Verified against | Replay key | Notes |
|---|---|---|---|---|---|
| `oauth_id_jag` | M1 | `jwt-bearer` assertion, or RFC 8693 `subject_token_type=urn:ietf:params:oauth:token-type:id-jag`, from an authenticated confidential client | the provider record's issuer and `jwks_url`; `typ` equals the ID-JAG media type from the pinned draft; `aud` equals the local AS issuer; `client_id` equals the authenticated client; `resource`, when present, equals the advertised protected resource | `(issuer, jti)`, single use | `exp - iat <= max_assertion_lifetime_secs` |
| `entra_jwt` | M1 | bearer at the edge, or RFC 8693 `subject_token_type=urn:ietf:params:oauth:token-type:jwt` | the provider record's tenant-specific Entra `jwks_url`; `iss` equals the record's issuer, which must be tenant-specific (multi-tenant `common` or `organizations` issuers reject); `aud` is in the record's `trust_boundary.allowed_audiences` (the provider app ID URI); principal is the claim the record's `subject_mapping.principal_source` names (`oid` for Entra records), and a token without it denies | `(issuer, uti)`, one root per token | ordinary Entra application and workload tokens; D5 lifetime and kill latency |
| `entra_agent_id` | M2 | bearer at the edge, or RFC 8693 `subject_token_type=urn:ietf:params:oauth:token-type:jwt` | as `entra_jwt`, against the rule's provider record; the agent-identity discriminator claim is present (D14) | `(issuer, uti)`, one root per token | added beside `entra_jwt`; discriminator claim name pinned at build start; rules of this kind reject at load before M2 |
| `oidc_jwt` | M1 | bearer at the edge (today's generic OIDC JWT path) | the provider record's issuer, `trust_boundary.allowed_audiences`, and its `jwks_url` or inline `jwks` | `(issuer, jti)` when present, else the token-bytes digest | Microsoft Entra issuers reject at load (D14) |
| `oauth_introspection` | M1 | bearer at the edge (today's introspection path) | RFC 7662 response from the provider record's `introspection_url`, `active: true` | token-bytes digest | evidence is the introspection response digest |
| `chio_local_as` | M1 | access token from the local AS `authorization_code` flow, or RFC 8693 re-exchange of such a token (`subject_token_type=urn:ietf:params:oauth:token-type:access_token`) | local AS key | local token `jti`; a re-exchange consumes the subject token's `jti` once | today's local OAuth path. A re-exchanged root's scope is the subject root's scope narrowed by the requested `scope` and `resource`, and its `assertion_exp` equals the subject root's. Re-exchange is open to the client the subject token was issued to, including public clients, because it can only narrow |
| `chio_operator_key` | M1 | operator-issued root through the admin route | pinned operator key | admin request id | replaces direct unanchored issuance |
| `operator_static_bearer` | M1 | `--auth-token` static bearer at the edge | constant-time comparison against the SHA-256 of the configured token | token-bytes digest plus root expiry, one live root per token | operator-issued root naming the rule's operator-configured `principal`; a fresh root is minted when the previous one expires. Identity is operator-attested and carries no IdP evidence. Scope: development, tests and conformance |

Bearer intake (`operator_static_bearer`, `oidc_jwt`, `oauth_introspection`, `entra_jwt`, `entra_agent_id`) maps a token to its root by the SHA-256 of the exact token bytes. The replay key separately enforces at most one root per assertion: a different token whose replay key is already bound denies. Replay keys are namespaced by kind and issuer, so one issuer's `jti` values cannot collide with or block another's.

`operator_static_bearer` rules:

- The rule names `principal` (an operator-chosen identifier such as `dev:alice`) and `tenant_value`. The token alone never confers a principal. With `--auth-token` set and no `operator_static_bearer` rule, or a rule without `principal`, startup refuses. A rule of this kind without `--auth-token` also refuses startup.
- Exactly one `operator_static_bearer` rule may exist. `serve-http` holds only the token's SHA-256 after startup; the token is never written to the state directory, receipts or logs.
- The delegation context records `issuer = "urn:chio:operator"`, the committed principal and tenant, and no `key_snapshot_digest`, `kid`, `alg` or `artifact_digest`.
- The verifier's identity root column for this kind is at most `asserted`: the provider's operator states the principal.
- Revocation by `anchor_subject` or `root_policy_rule` denies the token's next root and every call under the live one (section 7.11).

### 7.3 `chio.delegation-context.v1` (content-addressed, unsigned, bound through the root signature)

```json
{
  "schema": "chio.delegation-context.v1",
  "anchor": {
    "kind": "oauth_id_jag",
    "issuer": "https://acme.okta.com",
    "provider_record_id": "acme-okta",
    "provider_identity_digest": "sha256:5c0e...",
    "key_snapshot_digest": "sha256:31bb...",
    "kid": "k-okta-1",
    "alg": "RS256",
    "artifact_digest": "sha256:e0c4...",
    "artifact_retained": false,
    "replay_key_digest": "sha256:d2e1...",
    "token_iat": 1792234790,
    "token_exp": 1792235090,
    "subject": { "commit": "sha256:5a1f...", "salt_ref": "anchor.sub" },
    "tenant": { "commit": "sha256:91c0...", "salt_ref": "anchor.tenant" },
    "claims": {
      "client_id": "mcp-client-claude",
      "scope": ["crm.read", "crm.write"]
    }
  },
  "exchange": {
    "exchange_key": "ed25519:9f2c...",
    "exchanged_at": 1792234795,
    "request_digest": "sha256:0b77...",
    "holder": "edge_session"
  },
  "root_policy_rule_id": "okta-crm-agents",
  "effective_root_scope_hash": "sha256:c3d2..."
}
```

Rules:

- `artifact_digest` is SHA-256 of the exact compact JWS bytes received.
- `provider_record_id` and `provider_identity_digest` name the provider record the exchange verified against and the digest of its identity projection (section 7.4), which equals the matched rule's. `issuer` equals the record's issuer. Both members are present for provider-backed kinds and absent for `chio_local_as`, `chio_operator_key` and `operator_static_bearer`.
- Decoding is strict (G18): an unknown member in the context, `anchor`, `exchange`, a commitment object or `claims` rejects. `claims` keys are exactly the rule's `recorded_claims` names.
- `artifact_retained` (D7, M2) is `true` only for `oauth_id_jag` under a rule with `retain_idp_artifact: true`. The retained token is stored in the evidence store keyed by `artifact_digest` and never in the context, receipts or logs. Every other kind is always `false`.
- `subject` and `tenant` are always salted commitments with field-specific domains: `commit = SHA-256(domain || salt || utf8(value))`, where `domain` is `chio.delegation-context.subject.v1\0` or `chio.delegation-context.tenant.v1\0` and the salt is 32 bytes from the injected `Rng`, fresh per context. A subject opening therefore cannot be presented as a tenant opening. Salts live in the disclosure store under `salt_ref`.
- `claims` holds only the claims the matched rule names in `recorded_claims`, each as plain or committed per the rule. A committed claim uses `SHA-256("chio.delegation-context.claim.v1\0" || utf8(name) || 0x00 || salt || canonical_json(value))` with its own 32-byte salt.
- `holder` is `edge_session` or `caller` (section 6.5).

### 7.4 `chio.root-policy.v1` (signed by the provider's policy key), provider records and `chio.idp-key-snapshot.v1` (signed by the exchange key)

```json
{
  "schema": "chio.root-policy.v1",
  "policy_id": "rp_acme_prod",
  "policy_key": "ed25519:policy...",
  "exchange_keys": ["ed25519:9f2c..."],
  "rules": [
    {
      "rule_id": "okta-crm-agents",
      "match": {
        "anchor_kind": "oauth_id_jag",
        "provider_record_id": "acme-okta",
        "provider_identity_digest": "sha256:5c0e...",
        "allowed_algs": ["RS256"],
        "claims": { "client_id": ["mcp-client-claude"] }
      },
      "idp_scope_projection": { "crm.read": ["crm/search", "crm/get"], "crm.write": ["crm/update"] },
      "ceiling_scope": { "grants": ["..."] },
      "ceiling_scope_hash": "sha256:...",
      "recorded_claims": { "client_id": "plain", "scope": "plain" },
      "holder_classes": ["edge_session", "caller"],
      "capability_ttl_secs": 300,
      "max_assertion_lifetime_secs": 300,
      "max_clock_skew_secs": 30,
      "retain_idp_artifact": false
    }
  ],
  "disclosure": {
    "default": "committed",
    "tools": {
      "crm/search": { "parameters": { "inline_fields": ["/query"] }, "result": { "inline_fields": [] } }
    }
  },
  "valid_from": 1792000000,
  "valid_until": 1799999999,
  "signature": "..."
}
```

Policy key and validity:

- `policy_key` must equal the policy key pinned in the `serve-http` configuration (`--root-policy-key`). A self-asserted key proves nothing, so a mismatch refuses startup.
- `valid_from` and `valid_until` are checked at startup and on every exchange and admission against the injected clock. Outside the window, startup refuses and running exchanges and admissions deny.
- Exactly one policy is loaded. A root whose `root_policy_digest` names another policy denies. Every policy a bundle's roots reference is exported with the bundle.

Anchor rules:

- Provider-backed kinds (`oauth_id_jag`, `entra_jwt`, `entra_agent_id`, `oidc_jwt`, `oauth_introspection`) require `provider_record_id` and `provider_identity_digest` in `match`. The rule holds no issuer, key location, endpoint, audience, tenant claim or principal claim; those come only from the provider record (G17). A token matches a rule only when its `iss` equals the issuer of the rule's provider record and the rule's other `match` members hold. Keys are fetched only from the record's `jwks_url` or taken from its inline `jwks`. Token header members that name key material (`jku`, `x5u`, `jwk`, `x5c`) and any `crit` member reject.
- The effective root scope is `ceiling_scope ∩ projection(idp scope values)`. A scope value absent from `idp_scope_projection` denies the exchange. An IdP that sends no scope gets the empty projection, which denies.
- Exactly one rule must match. Zero or more than one denies.
- `capability_ttl_secs` defaults to 300. `max_assertion_lifetime_secs` defaults to 300 and applies to `oauth_id_jag`; for `entra_jwt` and `entra_agent_id` it must be absent (Entra lifetimes are set by Entra, and D5 governs).
- `max_clock_skew_secs` is bounded to at most 60 at load time.
- `retain_idp_artifact` is allowed only on `oauth_id_jag` rules (D7) and rejects at load before M2.
- `entra_agent_id` rules reject at load before M2. An `oidc_jwt` rule whose provider record has a Microsoft Entra issuer always rejects (D14).
- `principal` and `tenant_value` are required on `operator_static_bearer` rules and rejected on every other kind. `provider_record_id`, `provider_identity_digest`, `allowed_algs` and `idp_scope_projection` are absent on that kind; its effective root scope is `ceiling_scope`. `chio_local_as` and `chio_operator_key` rules carry no provider members either.
- Decoding is strict (G18): an unknown member in the policy, a rule, `match`, `disclosure` or a `tools` entry rejects at load, even under a valid policy signature.

Disclosure rules (D2):

- `default` is `committed` and is the only allowed value in v1.
- `tools.<server/tool>.parameters.inline_fields` and `.result.inline_fields` are RFC 6901 JSON pointers. Only listed fields may appear in plaintext in a receipt for that tool. A tool not listed is fully committed.
- Inline fields are copied into `action.parameters_inline` or `result_inline` as a sparse object containing only those pointers. The commitments still cover the full arguments and the full result.
- In M1 a non-empty `tools` map rejects at load (section 13.1).

Load rules: the policy is loaded at startup. A policy that fails signature, pinned-key match, validity window, schema, ceiling-hash recomputation, pointer syntax or bound checks refuses startup. A provider-backed rule whose record is missing from the registry, of the wrong record kind, invalid, lacking a member its kind needs, or whose identity digest differs from `provider_identity_digest` also refuses startup. A disabled record does not refuse startup; it denies at runtime.

Provider records (G17). The enterprise provider registry (`chio.enterprise-providers.v1`) is the one source of provider identity. A record referenced by a rule must be valid and carry:

- record kind `oidc_jwks` for `oauth_id_jag`, `entra_jwt`, `entra_agent_id` and `oidc_jwt` rules, with `issuer` and exactly one of `jwks_url` (`https`) or an inline `jwks` (for issuers without a published key endpoint; it replaces `--auth-jwt-public-key`). The exchange never follows `discovery_url`. `entra_jwt`, `entra_agent_id` and `oidc_jwt` records also carry a non-empty `trust_boundary.allowed_audiences`; an `oauth_id_jag` token's `aud` is always the local AS issuer;
- record kind `oauth_introspection` for `oauth_introspection` rules, with `issuer` and an `https` `introspection_url`. The client credentials the edge presents to that endpoint are `serve-http` secrets and never appear in the registry;
- `subject_mapping.principal_source` naming the one claim that is the principal, and `subject_mapping.tenant_id_field` naming the tenant claim (`iss` for per-org Okta issuers, `tid` for Entra). The tenant claim feeds the tenant tag (section 7.12);
- `provenance.trust_material_ref`, as the registry already requires.

Scim and saml records are never referenced by a rule. The record member `provider_profile` is deleted (it duplicated the rule's `anchor_kind`).

```json
{
  "schema": "chio.enterprise-provider-identity.v1",
  "provider_id": "acme-okta",
  "kind": "oidc_jwks",
  "issuer": "https://acme.okta.com",
  "jwks_url": "https://acme.okta.com/oauth2/v1/keys",
  "audiences": [],
  "subject_mapping": { "principal_source": "sub", "tenant_id_field": "iss" },
  "trust_material_ref": "okta-org-acme"
}
```

The identity projection holds the record's id, kind, issuer, key source (`jwks_url`, `jwks` or `introspection_url`), audiences, subject mapping and trust material reference. It excludes `enabled`, provenance labels other than `trust_material_ref`, and `validation_errors`. `provider_identity_digest = SHA-256("chio.enterprise-provider-identity.v1\0" || canonical_json(projection))`. The projection is unsigned and content-addressed, decodes strictly (G18), and is exported in bundles so a verifier can recompute the digest.

Runtime rules: every exchange, and every admission under a root whose anchor names a provider record, loads the registry once (bounded, 16 MiB cap) and checks the record against that one version. A missing, disabled or invalid record, a record of the wrong kind, or a recomputed identity digest that differs from the rule's denies. An unreadable or invalid registry answers HTTP 503 with the load error on the token endpoint and bearer intake, and denies admission. There is no cached registry and no fallback copy.

Producers without a root policy (`chio mcp serve`, `chio run`, the local kernel, `api protect` before M3, cage and broker receipts) emit fully committed receipts. Plaintext in a receipt always requires a signed root policy referenced by digest.

```json
{
  "schema": "chio.idp-key-snapshot.v1",
  "issuer": "https://acme.okta.com",
  "source": "https://acme.okta.com/oauth2/v1/keys",
  "keys": [ { "kid": "k-okta-1", "kty": "RSA", "alg": "RS256", "n": "...", "e": "AQAB" } ],
  "observed_at": 1792230000,
  "exchange_key": "ed25519:9f2c...",
  "signature": "..."
}
```

The exchange writes a snapshot each time its fetched key set changes. For a record with an inline `jwks`, `source` is `registry:<provider_id>` and a snapshot is written when the inline set changes. A snapshot is in force from `observed_at` until the next snapshot's `observed_at` for the same issuer. Each delegation context names the snapshot and `kid` it used. A snapshot is the provider's statement of what the IdP published. It is not IdP evidence, so an auditor who wants the identity root `verified` pins the IdP's keys in its own trust file (section 7.12).

JWKS documents are accepted only when they parse within a size cap, every used key has `use` absent or `sig`, the key's `alg` (when present) matches the token `alg`, and RSA moduli are at least 2048 bits. Keys failing these checks are dropped from the set.

### 7.5 `chio.capability-presentation.v1` (MCP `_meta.chioCapability`)

`chioCapability` is a new member of the closed `_meta` name list (T28).

```json
{
  "schema": "chio.capability-presentation.v1",
  "leaf": { "schema": "chio.capability.v1", "...": "..." },
  "ancestors": [ { "schema": "chio.capability.v1", "...": "root" }, { "...": "parent" } ],
  "delegation_context": { "schema": "chio.delegation-context.v1", "...": "..." }
}
```

- `ancestors` is ordered root to parent, matching PROTOCOL W1.1. A root presented alone has `ancestors: []`. In M1 only `ancestors: []` is accepted (section 6.4).
- `delegation_context` is required when the presenter is not the session holder, so the verifier can recompute `context_digest`.
- Unsigned envelope. Every member inside is verified independently. Decoding is strict (G18): an unknown member in the envelope or in any member it carries rejects the presentation.

### 7.6 `chio.receipt.v1` (in place, protocol-wide): commitments, `disclosure`, `authority`

Changes to `ChioReceiptBody` (`crates/core/chio-core-types/src/receipt/body.rs`) and `ToolCallAction` (`receipt/decision.rs`) apply to every producer (D2):

1. `action.parameters` and `action.parameter_hash` are replaced by `action.parameter_commitment` and optional `action.parameters_inline`.
2. `content_hash` is replaced by `content_commitment` and optional `result_inline`. The signer recomputes the commitment from the content preimage and the salt inside its own trust boundary. WYSIWYS is kept. No signing path accepts a caller-supplied hash or commitment; a producer that holds only a hash today receives the preimage (G3).
3. `redaction_mode` is replaced by a `disclosure` block. `RedactionMode` is deleted. Builder task in M0: inventory every producer of `summary` and `redacted` and record how each maps to committed-with-inline-fields or fully committed.
4. New top-level `authority` block, present whenever the exercised capability carries `root_anchor`.
5. A receipt with an `authority` block must omit `tenant_id` (T27); signing fails otherwise. The tenant is carried only as the delegation context commitment and the unsigned tenant tag.

```json
{
  "action": {
    "parameter_commitment": { "alg": "sha256-salted", "value": "sha256:9b1f...", "salt_ref": "params" },
    "parameters_inline": { "query": "acme renewal" }
  },
  "content_commitment": { "alg": "sha256-salted", "value": "sha256:44aa...", "salt_ref": "content" },
  "disclosure": {
    "policy_digest": "sha256:aa90...",
    "parameter_inline_fields": ["/query"],
    "result_inline_fields": []
  },
  "authority": {
    "root_anchor": { "kind": "oauth_id_jag", "context_digest": "sha256:...", "root_policy_digest": "sha256:...", "anchored_at": 1792234795, "assertion_exp": 1792235090 },
    "chain_digest": "sha256:c0de...",
    "chain_depth": 0,
    "holder": "caller"
  }
}
```

Commitment rules:

- `value = SHA-256(domain || salt || preimage)` where the domain is `chio.receipt.parameters.v1\0` or `chio.receipt.content.v1\0`, the salt is 32 bytes drawn per receipt per field from the producer's host `Rng`, and the preimage is the existing canonical preimage (RFC 8785 canonical arguments; the WYSIWYS content preimage for outputs). The salt is fixed-length, so the concatenation is unambiguous.
- A verifier selects the domain from the commitment's position in the receipt, never from the opening.
- The content preimage has three forms. A value output uses the canonical JSON of the result. An empty output (no result) uses the zero-length byte string, so its commitment is `SHA-256(domain || salt)`. A stream output uses the concatenation of the lowercase hex SHA-256 of each canonical chunk; a stream with no chunks is an empty output. A verifier derives the preimage from its own copy of the output (or from the absence of one) and never from an opening's `payload`: a `payload: null` opening is salt only and supplies no preimage, so the literal `null` is never an output preimage. Per-chunk digests are not written to any signed field, metadata or evidence, because they are unsalted.
- Salts are never in the signed body. They are returned to the producer's host with the signed receipt and written to the disclosure store keyed by `(receipt_id, salt_ref)` where a store exists.
- `disclosure.policy_digest` is required when either inline list is non-empty and must name the loaded root policy. The inline lists must equal the policy's lists for that tool. A verifier with the policy checks that every inline field was authorized (A5) and that each inline value matches the opened commitment when openings are available.
- A receipt with no inline fields omits `policy_digest` and both lists are empty.
- `chain_digest = SHA-256("chio.receipt.chain-digest.v1\0" || canonical_json([root, ..., parent, leaf]))` over the full signed tokens.
- Guard `evidence` entries and `metadata` must not contain argument or result values outside the inline fields. Enforcement is in section 8.4.
- Decoding is strict (G18): an unknown member in a commitment, `disclosure`, `authority` or its `root_anchor`, or in any later block (`enforcement`, `settlement`), rejects the receipt at decode.

Caller copy (D11, M2): every MCP `tools/call` response from `serve-http` carries `_meta.chioReceipt` with the signed receipt and a `chio.receipt-disclosure.v1` opening that contains the salts for that receipt's parameters, content and anchor subject and tenant, without payloads (the caller holds its own arguments, result and identity). `chioReceipt` joins the closed `_meta` name list in M2.

### 7.7 `chio.receipt-disclosure.v1` (unsigned opening, self-verifying)

```json
{
  "schema": "chio.receipt-disclosure.v1",
  "receipt_id": "5a1f...c4",
  "openings": [
    { "salt_ref": "params", "salt": "b64u:...", "payload": null },
    { "salt_ref": "content", "salt": "b64u:...", "payload": { "...": "canonical result" } },
    { "salt_ref": "anchor.sub", "salt": "b64u:...", "payload": "00u1abcd..." }
  ]
}
```

- An opening with a `salt` and `payload: null` is valid only in the caller copy, in `caller` bundles (section 7.12) and in the AuthZEN response to the PEP that sent the arguments (section 7.9). Export refuses to write salt-only openings in auditor profiles.
- A verifier opens a commitment by recomputing it. A mismatch marks that field `rejected` and the receipt as tampered disclosure.
- A verifier rejects an opening document in which the same `salt` value appears for more than one `salt_ref`, and marks the receipt as tampered disclosure. A producer draws a fresh salt for every field.
- Decoding is strict (G18): an unknown member in the document or in any opening rejects it.
- Deleting a receipt's openings from the disclosure store makes its commitments permanently hiding and leaves the signed receipt valid (erasure path).

### 7.8 Producer salt sources (D2)

| Producer | Salt source |
|---|---|
| Hosted kernel (`chio-kernel`, `serve-http`, `api protect`, `chio run`, `chio mcp serve`) | OS RNG through the existing `Rng` seam |
| Portable core (`chio-kernel-core`) | host-supplied `Rng` |
| Browser and Workers WASM (`chio-kernel-browser`) | `globalThis.crypto.getRandomValues` through `getrandom`'s js backend. `WebCryptoRng::try_new` stops calling `web_sys::window()` (`src/rng.rs:71`), which does not exist in Workers |
| Mobile (`chio-kernel-mobile`, UniFFI) | OS RNG |
| C ABI (`chio-cpp-kernel-ffi`) | OS RNG inside the library |
| Security producers (cage, secret broker, other `chio.receipt.v1` emitters) | host `Rng` passed into their signing path |
| Other std processes: control plane (keyring projection, native evidence, response simulation, SCIM deprovision, verified-fix evidence), `chio-http-core`, `chio-acp-proxy`, `chio-otel-receipt-exporter`, `chio-mercury`, `chio-wall` | OS RNG through the `Rng` seam |
| Harness, conformance and fixture producers (`chio-runtime-harness`, `chio-conformance` native suite, `chio-attest-loopback`, `chio proof fixture` generators) | seeded deterministic `Rng` injected through the same seam; output is fixture material only |

Rule (G3): a producer draws salts from the `Rng` seam of the process that signs. The inventory assigns every producer to one row. A producer that holds only a hash today (ACP relays, verified-fix evidence, fixture re-signers) receives the preimage over its existing channel, and a fixture that re-signs a recorded hash is regenerated from its recorded preimage.

The FFI and WASM relay seam (T14) is replaced: those adapters pass the unsigned body plus the parameter and content preimages, and the core computes commitments and salts. `sign_receipt_relaying_trusted_body` is deleted, which also removes the one place where a caller-asserted content hash was trusted. Out-of-workspace emitters (the Lambda extension under `sdks/lambda/`) adopt the format in the same PR or are deleted.

### 7.9 `pdp_decision` receipts and the AuthZEN profile (M2, `serve-http`)

Closed enums extended in place (`receipt/kinds.rs`): `ReceiptKind::PdpDecision` (`pdp_decision`), `BoundaryClass::PreventExternal` (`prevent_external`), `TrustLevel::Delegated` (`delegated`). Coherence rule: `pdp_decision` requires `prevent_external` and `delegated`, and every other combination with any of the three rejects. A required `enforcement` block:

```json
"enforcement": {
  "pep_id": "kong-prod-eu",
  "pep_key": "ed25519:pep...",
  "pep_profile": "authzen_1_0_fail_closed",
  "request_id": "req_01J...",
  "decision_expires_at": 1792234930
}
```

A `pdp_decision` receipt has no `content_commitment` (Chio never sees the result) and its `decision` member is present. PROTOCOL 6.1 is unchanged: only `mediated_decision + prevent + Allow` is Chio-enforced authorization. Verifiers render a `pdp_decision` Allow as "authorized by Chio, enforced by the named PEP" and only when `pep_key` is pinned in the trust file.

AuthZEN 1.0 mapping (pin at build start: OpenID AuthZEN Authorization API 1.0 final). Endpoints on `serve-http`: `POST /access/v1/evaluation`, `POST /access/v1/evaluations`, `GET /.well-known/authzen-configuration`.

```json
{
  "subject": {
    "type": "chio_capability",
    "id": "cap_01J...",
    "properties": {
      "presentation": { "schema": "chio.capability-presentation.v1", "...": "..." },
      "dpop_proof": "..."
    }
  },
  "action": { "name": "search", "properties": { "operation": "invoke" } },
  "resource": { "type": "chio_tool", "id": "paid-search/search" },
  "context": {
    "request_id": "req_01J...",
    "parameters": { "...": "canonical arguments; committed in the receipt per policy" }
  }
}
```

Response: `{"decision": true|false, "context": {"chio": {"receipt": {...signed pdp_decision...}, "opening": {...chio.receipt-disclosure.v1 with the params salt only...}, "reason_code": "urn:chio:error:...", "expires_at": 1792234930}}}`. The PEP opening never carries the anchor subject or tenant salts, because the PEP is not necessarily the tenant. The PEP authenticates with mTLS or a per-PEP token; its identity selects `pep_id` and `pep_key` from the PEP allowlist. An unlisted PEP gets HTTP 401 and no receipt.

### 7.10 `settlement` block and `chio.settlement-closure.v1` (M3)

Typed asset, in place in `MonetaryAmount` (`crates/core/chio-core-types/src/capability/scope.rs`): `currency: String` becomes `asset`, a closed grammar `iso4217:<CODE>` or `caip19:<chain>/<namespace>:<reference>`. A child's asset must equal its parent's. A tool's price asset must equal the cap's asset (D13). No conversion between assets inside authority.

Receipt `settlement` block:

```json
"settlement": {
  "rail": "x402",
  "scheme": "exact",
  "state": "settled",
  "asset": "caip19:eip155:84532/erc20:0x036c...",
  "amount": "250000",
  "pay_to": "eip155:84532:0xprovider...",
  "hold_id": "hold_01J...",
  "rail_refs": [
    { "kind": "x402.payment_requirements", "digest": "sha256:..." },
    { "kind": "x402.settlement_response", "id": "eip155:84532:0x5e9c...", "digest": "sha256:..." }
  ]
}
```

`state` is closed: `settled`, `authorized_pending`, `failed`. `rail_refs[].kind` is closed: `x402.payment_requirements`, `x402.payment_payload`, `x402.settlement_response`. Digests are over canonical JSON of the decoded base64 payloads.

```json
{
  "schema": "chio.settlement-closure.v1",
  "terminal_receipt_id": "5a1f...c4",
  "hold_id": "hold_01J...",
  "rail": "x402",
  "state": "settled",
  "asset": "caip19:eip155:84532/erc20:0x036c...",
  "amount": "250000",
  "rail_refs": [ { "kind": "x402.settlement_response", "id": "eip155:84532:0x...", "digest": "sha256:..." } ],
  "observed_at": 1792234990,
  "kernel_key": "ed25519:9f2c...",
  "signature": "..."
}
```

Exactly one closure may exist per `authorized_pending` terminal receipt. Its `hold_id` must match. The mutable reconciliation sidecar stays an operator view and is never authority (existing PROTOCOL 6.4 rule).

Tool pricing lives in the signed tool manifest (`crates/platform/chio-manifest`): per tool, `pricing { asset, amount, scheme: "exact", pay_to, networks: [...] }`. A manifest price the edge cannot express as x402 `accepts` rejects at manifest load.

### 7.11 Revocation (D3)

Provider-side revocation (M1). The existing `/admin/revocations` route (T17) gains the target kinds below and writes to the existing SQLite revocation store, which moves under the state directory. Closed target kinds:

| Target | Effect |
|---|---|
| `capability_id` | that capability and every descendant (existing cascade) |
| `root_policy_rule` | every root minted under the rule |
| `anchor_subject` | every root whose principal has the given subject tag. The admin supplies issuer and plaintext subject; the store computes the subject tag (section 7.12) and keeps only the tag |
| `tenant_tag` | every root in the tenant (the admin supplies issuer and tenant value; only the tag is stored) |
| `replay_key` | the root minted from one assertion, by `(kind, issuer, jti or uti)` |

Each anchored root row stores its rule id, subject tag and tenant tag, so every target is an indexed equality lookup at exchange and at admission.

Linearization: a revocation is one serving-writer transaction on the state-directory database, acknowledged after it commits and the authority anchor syncs. Let T be that commit. (1) Every budget authorize-hold transaction, which is where an admission commits, that begins after T denies, and the call does not dispatch. (2) Every root-exchange mint transaction that begins after T and matches the entry refuses. (3) A call admitted before T may dispatch. Its budget capture and its native dispatch capture re-check revocation inside the capture transaction, and a capture that begins after T refuses. By then the upstream effect has run and streamed chunks may already have reached the caller; the remaining output is withheld and the call ends with a revocation denial. (4) A call that captured before T reaches the allowed-receipt check, which is one read per id in the call's chain (the leaf, then each ancestor), each separate from the others and from the receipt append. If the read of the id the revocation marked begins after T the allowed receipt is refused; if it began before T the allowed receipt is appended, even when later reads or the append land after T. An acknowledgement therefore guarantees (1) to (3) and does not guarantee that no allowed receipt is appended after it, nor that a call admitted before it completes. 'Next call' in this spec means a call whose budget authorize-hold begins after the acknowledgement.

A denied call's receipt names the matching revocation entry id in its guard evidence. Revocation entries are exported in bundles (with tags, never plaintext subjects or tenants).

IdP-driven expiry (M1) is the root lifetime rule in sections 6.2 and 6.3. No IdP push channel is consumed in v1.

Before M1 item 5 starts, the revocation store changes here are reconciled with the parallel lead's coop2c revocation-root work so that one store shape results (D17).

Caller-side revocation (M2):

```json
{
  "schema": "chio.revocation-request.v1",
  "target_capability_id": "cap_01J...child",
  "revoker_key": "ed25519:41aa...",
  "presentation_digest": "sha256:...",
  "reason": "subagent_retired",
  "issued_at": 1792235000,
  "signature": "..."
}
```

- Submitted to `POST /v1/revocations` on `serve-http`. The provider accepts it only if `revoker_key` is the subject of a strict ancestor of the target in a retained presentation named by `presentation_digest`, and that ancestor is not itself revoked.
- A caller can therefore revoke only its own delegated descendants. It cannot revoke its own root (that is the IdP's or provider's call) or a sibling's branch.
- `issued_at` must be within the rule's clock skew of the provider's clock. Duplicate requests are idempotent.
- The accepted request is stored and exported. The provider answers with the revocation entry id.

### 7.12 Tenant and subject tags, `chio.evidence_export_manifest.v1` (in place) and `chio.verifier-trust.v1`

Tags (D8):

- `tenant_tag` and `subject_tag` are keyed index values of the provider's tenant index key set (`--tenant-index-keys <dir>`, the set the committed receipt binding uses), with its HKDF purpose subkeys, `key_id` and rotation modes as the M1 item 2 plan defines them (`docs/superpowers/plans/2026-10-20-m1-item2-committed-receipts.md`, Task 5, "Key set and provisioning" and "Purpose subkeys"): `tenant_tag = HMAC-SHA256(K[tenant-tag], "chio.tenant-tag.v1" || 0x00 || issuer || 0x00 || tenant_value)`, where `issuer` is the provider record's issuer and `tenant_value` is the claim named by the record's `subject_mapping.tenant_id_field` (G17), and `subject_tag = HMAC-SHA256(K[subject-tag], "chio.subject-tag.v1" || 0x00 || issuer || 0x00 || subject)`.
- Each stored tag carries its generation `key_id`; new tags use the active generation. Tags rotate by all-generation match: no plaintext is stored, so a lookup or revocation match computes the candidate from the request or admin plaintext under every loaded generation and matches on `(key_id, value)`. A retired generation stays loaded while any stored tag or revocation entry references it, startup refuses when one is missing, and an unknown `key_id` refuses. A path that holds no plaintext never compares tags: a revocation fans out from the admin plaintext to every matching root, the mint check recomputes candidates from the exchange evidence, and admission reads revoked capability ids. So a revocation recorded under one generation still denies roots minted or admitted after a rotation. The keys never leave the process and are not signing keys.
- Tags are stored in SQLite columns beside each root and receipt. They are not part of any signed artifact. No plaintext tenant id or subject is stored outside the salted commitments in the delegation context.

New manifest members:

- `disclosure_profile`: closed, one of `caller` (receipts for one tenant; salts for those receipts' parameters, content, and the tenant's own principals and tenant commitment; no payloads), `auditor_full` (salts and payloads, M2), `auditor_hash_only` (no salts, no payloads).
- `tenant_tags`: required for `caller`; the tenant's tag set, one keyed value `(key_id, tag)` per loaded generation. The bundle contains exactly the receipts whose stored `(key_id, tag)` is in the set, so an export after a rotation includes receipts tagged under retired generations.
- New artifact roles: `capability_presentation`, `delegation_context`, `root_policy`, `enterprise_provider_identity` (the identity projection of every provider record a bundle's roots name), `idp_key_snapshot`, `idp_artifact` (retained ID-JAG, auditor profiles only, D7, M2), `receipt_disclosure`, `revocation_entry`, `revocation_request` (M2), `settlement_closure` (M3), `pdp_decision_receipt` (M2).
- The manifest is signed by the kernel key (existing commitment artifact pattern, `chio.evidence_export_commitment.v1`).

The tenant confirms the bundle is its own by opening the subject and tenant commitments with the included salts. The verifier report carries `tenant_confirmed` and `principals_confirmed`. Each is true only when the commitments covering the exported receipts form a nonempty set that covers every exported receipt and every one of them opens: tenant commitments with the caller's tenant value, subject commitments against a principal the caller supplies. An empty bundle, a receipt without `authority`, or a missing context, opening or caller value leaves the member false.

`chio.verifier-trust.v1` is a local, unsigned file the verifying party writes and controls:

```json
{
  "schema": "chio.verifier-trust.v1",
  "kernel_keys": ["ed25519:9f2d..."],
  "exchange_keys": ["ed25519:9f2c..."],
  "root_policy_keys": ["ed25519:policy..."],
  "idp_keys": { "https://acme.okta.com": [ { "kid": "k-okta-1", "kty": "RSA", "n": "...", "e": "AQAB" } ] },
  "pep_keys": { "kong-prod-eu": "ed25519:pep..." },
  "checkpoint_keys": [],
  "required_columns": ["identity_root", "delegation_chain", "decision", "content"]
}
```

`idp_keys` is optional. A calling tenant knows its own IdP's keys and can pin them; without them the identity root column cannot exceed `observed` for a retained artifact (section 11.4).

### 7.13 OCSF 1.9 projection (M2, unsigned)

`crates/observability/chio-siem/src/ocsf.rs` moves from 1.3.0 to 1.9.0, class 6003 API Activity unchanged. Pin at build start: `ocsf-schema` tag `v1.9.0`, exact attribute names of the `delegation` and `record_integrity` additions. In M1 the 1.3.0 projection is updated only to read commitments instead of the deleted fields. Mapping in M2:

- `delegation` from `authority` (anchor kind, issuer, committed subject digest, `chain_depth`, `chain_digest`, `holder`).
- `record_integrity` with the receipt id, signature algorithm, kernel key id and signature value, so a SIEM consumer can fetch and verify the original receipt.
- `actor.authorizations[].decision` stays authorization only for trusted `mediated_decision + prevent + Allow` (existing rule, T18). `pdp_decision` maps to its own decision label naming the PEP.
- No argument, result, salt, tag or IdP token value appears. Policy-authorized inline fields are omitted from OCSF too.

## 8. Fail-closed rules

Every rule below denies, rejects at load, or refuses startup. None degrades to a weaker mode.

### 8.1 Exchange

- Unsupported `grant_type`, `subject_token_type` or `requested_token_type`.
- Client authentication: a `jwt-bearer` or `token-exchange` request from a public client, without a client assertion, with an assertion whose signature fails against the registered client key, whose `aud` is not the token endpoint URL, whose lifetime exceeds 60 s, or whose `jti` was already used.
- JWT header: `alg` not in the rule's `allowed_algs` (`none` and HMAC algorithms are never allowed); `typ` mismatch for `oauth_id_jag`; `kid` absent; any of `jku`, `x5u`, `jwk`, `x5c` or `crit` present.
- `kid` not in the current key set after at most one rate-limited refresh (section 9.2).
- Provider registry (G17): unreadable or invalid (HTTP 503, no exchange); the rule's record missing, disabled, invalid or of the wrong kind; the record's recomputed identity digest different from the rule's `provider_identity_digest`.
- Signature invalid. `iss` not exactly the provider record's issuer. `aud` not exactly the local AS issuer (ID-JAG) or not in the record's `trust_boundary.allowed_audiences` (Entra, OIDC JWT). ID-JAG `resource` present and not equal to the advertised protected resource.
- Time: `exp` or `iat` missing; `now >= exp + skew`; `iat > now + skew`; `nbf > now + skew`; for ID-JAG, `exp - iat > max_assertion_lifetime_secs`; computed root `expires_at <= now`. All time reads go through the injected authority clock.
- Replay key (section 7.2) missing where required, or already bound. The replay store is durable and retained until `exp + skew`.
- ID-JAG `client_id` not equal to the authenticated client.
- Token without the claim the provider record's `subject_mapping.principal_source` names, or, where the record names a `tenant_id_field`, without that claim. From M2, a token with the agent-identity discriminator claim matched against an `entra_jwt` rule, or one without it matched against an `entra_agent_id` rule. Any Entra issuer on an `oidc_jwt` rule's provider record.
- Static bearer token not equal to the configured token. Local AS re-exchange whose subject token is expired, revoked or already re-exchanged, or whose requested scope or `resource` is not a subset of the subject root's.
- Any string feeding a tag or commitment that contains a NUL character.
- Root policy: outside `valid_from`/`valid_until`; zero or more than one matching rule; a scope value missing from the projection; effective scope empty; requested holder class not in `holder_classes`; DPoP-required grants for a session-held root.
- JWKS endpoint unreachable, oversized or invalid: no exchange. Existing roots live until their expiry.
- Exchange signer failure: no mint.
- Any revocation entry matching the would-be root (rule, subject tag, tenant tag, replay key): no mint.

### 8.2 Edge admission

- Root without `root_anchor`, signed by a key outside the root policy's `exchange_keys`, or naming a `root_policy_digest` that is not the loaded policy. Loaded policy outside its validity window.
- Strict decoding (G18, G19): an unknown member at any level of a presented capability, presentation or delegation context, including an added or altered `algorithm` member. The rejection happens at decode, before any verifier is chosen.
- Provider record (G17), for a root whose anchor names one: the registry, loaded once for this request, is unreadable or invalid, or the record is missing, disabled, invalid, or its identity digest differs from the one the delegation context names.
- Root `expires_at > root_anchor.assertion_exp`.
- `context_digest` mismatch against the presented or stored delegation context, or any binding in section 7.1 failing (`assertion_exp` against `token_exp`, issuer key against `exchange_key`, scope hash against `effective_root_scope_hash`, subject against `holder`).
- Delegated token whose `root_anchor` differs from its root's. Ancestor evidence missing, reordered, unsigned or not covering every hop (existing W1.1 rule). Any non-empty `ancestors` before M2.
- Any token in the chain matched by a revocation entry. The revocation read happens in the admission transaction; a store error denies.
- Plain OAuth access tokens and IdP bearer tokens are accepted only as handles to an exchange-issued root (`chio_root` claim, or the token-digest mapping for bearer intake). A token with no stored root denies.

### 8.3 Startup refusals

`serve-http` refuses to start when: no root policy is configured, or it fails any load rule in section 7.4; a provider-backed rule exists and `--enterprise-providers-file` is not set, or the registry is unreadable or invalid; the root policy's `policy_key` differs from `--root-policy-key`; the state-directory lock is held by another process or the state directory is on a network filesystem (D4); the kernel signer is ephemeral (T7) or missing; any two of the exchange, kernel, policy and local AS keys are equal; a seed file, credential file or tenant index key file is readable by group or other or not owned by the process user; the tenant index key set has no active key, a key that is not 32 bytes or a duplicate `key_id`, or lacks the generation the state directory pins; a manifest price uses a chain id outside the testnet allowlist; durable admission is off; `--auth-token` is set without exactly one `operator_static_bearer` rule naming a `principal`, or such a rule exists without `--auth-token`; `--control-url` or `--control-token` is set; `--exchange-signer trust-control:<url>` is set without `--exchange-signer-credential-file` and `--exchange-signer-trusted-public-keys`. A trust-control signature outside the trusted set fails the mint (section 8.5), not startup. From M2: a KMS key's `GetPublicKey` result differs from the pinned public key in config. `api protect` gains the same refusals in M3.

### 8.4 Privacy

- Receipt assembly fails signing (the call denies) if `parameters_inline` or `result_inline` contains a pointer not authorized by the root policy for that tool, if any inline list is non-empty without a root policy, or if a receipt with `authority` carries `tenant_id`.
- Guard evidence and metadata: guards declare which evidence fields are safe under committed disclosure. Undeclared fields are dropped before signing. A guard that marks a field required and unsafe fails at load.
- Salt generation failure fails signing.
- Disclosure-store write failure after signing: the receipt is still appended (receipts are authority), the opening is marked lost, and an operator alert fires. The commitment then stays permanently hiding (Q-B5).
- Export refuses salt-only openings in auditor profiles, and refuses `caller` exports without `tenant_tags`.

### 8.5 Signer

- Seed-file signer (M1): a missing, unreadable or wrongly permissioned seed file refuses startup; there is no generated fallback key.
- Trust-control exchange signer (M1): an unreachable trust-control, a response of another kind or for another body, or a returned signature that does not verify under a key in `--exchange-signer-trusted-public-keys` fails the mint; no root is issued and there is no local fallback key.
- KMS signer (M2): call error, timeout, throttle, or a returned signature that fails local verification against the pinned key: signing fails, the call denies, readiness reports false. There is no local fallback key.

### 8.6 PDP and payment

- AuthZEN request from an unlisted PEP, without a presentation, with unknown `subject.type` or `resource.type`, or for a grant needing a hold, payment or output check.
- Price above caps, price asset different from cap asset (D13), `payTo` mismatch against the manifest, facilitator `/verify` invalid, `/settle` not settled: no dispatch.
- Settled amount different from the challenged amount: terminal receipt with `settlement.state = failed`, hold stays open for operator action.
- Settlement that matches no hold: dead-letter path (#1241), no credit.

### 8.7 Caller revocation requests (M2)

- Signature invalid; `revoker_key` not a strict-ancestor subject in the named retained presentation; ancestor revoked; target not a descendant; `issued_at` outside skew: reject with no state change.

## 9. Threat model

Assets: the provider's tools and data; the integrity of receipts; the caller's arguments and results; the binding between an IdP principal and the actions attributed to it; the provider's revenue on paid tools.

Adversaries: an external agent with a stolen or replayed token; a malicious calling agent operating within its own valid identity; a curious or compromised party holding a receipt bundle; a network attacker; an attacker with code execution on the edge host; a dishonest provider (from the caller's point of view).

### 9.1 Token replay

- **ID-JAG replay to the exchange.** `(issuer, jti)` single use with a durable replay store retained to `exp + skew`; `aud` pinned to the local AS issuer; confidential client authentication with replay-protected client assertions; `client_id` match. A stolen ID-JAG is useless without the client's private key, and a replayed ID-JAG denies across restarts.
- **Entra token replay.** Entra access tokens are bearer tokens. One root per `uti` means a stolen token yields at most one root lifetime (300 s default) of authority. Residual risk: a thief holding the token during that window has the agent's authority, and a thief holding several stolen unexchanged tokens gets one root per token until each expires. This is stated in copy (D5).
- **Static bearer.** Anyone holding the `--auth-token` value acts as the configured principal until the token is changed and the process restarted, or the principal is revoked. The identity is operator-attested only. Docs scope the mode to development, tests and conformance, and the M1 claims never describe it as an identity provider.
- **Capability replay.** Session-held roots never leave the edge. Caller-held roots require `_meta.chioDpopProof` for DPoP-required grants (existing per-call proof binding capability, tool, canonical arguments and sender key).
- **Access-token replay.** The access token is a handle; its lifetime equals the root's, and existing local AS sender constraints apply when the client uses them.
- **Single instance.** The replay store is correct only because there is one process (D4). The state-directory lock enforces that. Restoring a backup rewinds it (section 6.1).

### 9.2 IdP key rotation

- Today the JWKS is fetched once (T4), so a rotation breaks the edge until restart, and a withdrawn key stays trusted until restart.
- New behavior: keys come only from the `jwks_url` or inline `jwks` of the rule's provider record, whose identity digest the signed rule pins. Unknown `kid` triggers one refresh, rate-limited per issuer (at most one fetch per 60 s). A scheduled refresh (default every 15 min) removes keys the IdP has withdrawn. Every key-set change writes a new `chio.idp-key-snapshot.v1`.
- An attacker cannot force a refresh storm: the rate limit holds, and unknown-`kid` tokens deny while it is active. Header-supplied key locations (`jku`, `x5u`, `jwk`, `x5c`) reject, so a token cannot choose its own key.
- A compromised IdP key is the IdP's incident. Chio's exposure after the IdP withdraws the key is bounded by the next scheduled refresh plus the root lifetime.

### 9.3 Confused deputy

- **Audience confusion.** ID-JAG `aud` must be this AS. Entra `aud` must be this provider's app ID URI. The RFC 8707 `resource` parameter, and an ID-JAG `resource` claim when present, must equal the advertised protected resource.
- **Token pass-through.** The edge never sends the caller's IdP token or Chio access token upstream. Upstream credentials are the provider's own.
- **Tenant confusion.** Entra multi-tenant issuers reject. Each rule names exact issuers. Tenants are committed in the delegation context and tagged in the index.
- **Scope widening by the IdP.** Projection only removes. A Chio ceiling is never derived from IdP claims alone.
- **Cross-token capability use.** A session-held root is usable only by a request authenticating with the exact access token or bearer token that produced it. Presenting its capability id from any other token denies.
- **AuthZEN PEP impersonation.** PEP identity comes from mTLS or a per-PEP token, never from the request body.
- **Revocation-request abuse.** A caller can revoke only descendants of a capability it holds the subject key for (section 7.11).

### 9.4 Hash-only receipts and dictionary attacks on low-entropy arguments

- Unsalted hashes (T13) let anyone holding a receipt confirm a guess for a low-entropy argument or result. The fix is a per-receipt, per-field 256-bit secret salt, for every producer (D2). Without the salt the commitment hides the value; brute force over the salt is infeasible.
- Binding: opening a commitment to a different payload requires a SHA-256 second preimage, because the salt length is fixed and the domain is field-specific.
- The salt is the secret. Disclosing a salt without the payload to a party who does not already know the payload re-opens the dictionary attack. Salt-only openings therefore exist only for the calling tenant (caller copy and `caller` bundles) and for the PEP that sent the arguments, and export refuses them in auditor profiles.
- Tenant scoping (D8) keeps one tenant's salts out of another tenant's bundle.
- A caller who leaks its own bundle exposes its own low-entropy values. This is the caller's data and is documented.
- Per-receipt salts make identical arguments in different receipts unlinkable.
- Linkage through other fields remains: `tool_name`, timestamps, `capability_id`, `chain_digest` and the anchor `context_digest` are plaintext. One provider can always correlate calls under one root.
- Policy-authorized inline fields (M2) are plaintext by the provider's signed choice, visible to any verifier holding the policy.
- Guard evidence and metadata are the most likely leak path because they are free-form today. Section 8.4 closes it, and a property test with high-entropy marker values asserts that no argument or result value outside inline fields appears in any signed field (section 11.1).

### 9.5 Signing keys: seed files in M1, KMS from M2

- **M1, seed files.** An attacker with read access to the seed files, or code execution on the edge host, can sign roots and receipts for any timestamp, past or future, until the key is replaced and every verifier trust file updated. Receipts signed before such a compromise cannot be distinguished from forgeries by signature alone. M1 makes no key-custody claim (F11). Seed files must be mode 0600 and owned by the process user (section 8.3).
- **M2, KMS outage.** Outage, throttling or network partition from KMS stops all signing, so all mediated calls deny. This is intended (anti-goal: no second identity). With one instance (D4) there is no failover; readiness reports false so monitoring sees it.
- **M2, latency.** One KMS `Sign` per receipt adds a network round trip per call. The builder measures p50 and p99 on the verdict-matrix corpus against a real KMS key in the same region and records it.
- **M2, request quota.** KMS asymmetric signing has a per-account, per-region request quota (pin at build start). At the quota, calls deny.
- **Message size.** The signing wrapper (D6) makes every preimage 88 bytes, so KMS Ed25519 raw signing and P-256 digest signing both work for every artifact.
- **M2, edge host compromise.** An attacker with code execution can request signatures while it holds the host's KMS credentials. It cannot extract the key, and its signing ends when the credentials are revoked. Receipts signed before the compromise stay trustworthy, provided KMS audit logs bound the compromise window.

### 9.6 Dishonest provider (caller's view)

- The provider holds the exchange, kernel and policy keys. It can mint receipts for calls that never happened. From M2 the caller's defense is its own copy (D11): every receipt the caller received is signed, so the provider cannot later deny or alter it. In M1 the caller holds only what the provider exports, so it can check what a bundle contains but cannot detect a receipt the provider omitted.
- The identity-root column for bearer anchors attests "the provider's exchange says IdP X authenticated principal P". It becomes independently verifiable only for ID-JAG roots whose rule retains the artifact (D7, M2) and whose IdP key the verifier pins in `idp_keys`. A provider-signed key snapshot alone is the provider's statement, so the column stays `observed`; without a retained artifact it is `asserted`.
- The provider can retroactively claim a plaintext field was authorized only by signing a new root policy, whose digest would not match the receipt's `disclosure.policy_digest`.

### 9.7 Payment

- Price manipulation by the caller: prices come from the signed manifest; the payload amount must equal the challenge.
- Settlement to the wrong address: `payTo` comes from the manifest and is checked against the settlement response.
- Rehearsal-only enforcement (F2): the CAIP-2 testnet allowlist is compiled in for v1 (Base Sepolia `eip155:84532`, plus any others the builder pins). Mainnet ids reject at manifest and policy load.
- Facilitator compromise is out of Chio's control. Chio records what the facilitator returned and its digest; the verifier's settlement column is `asserted` unless the optional online on-chain check (`chio-verify --online`) confirms the transaction.

### 9.8 Provider registry

- **Unsigned, mutable source.** The registry file is not signed. A party who can write it can disable or remove providers, which denies their exchanges and calls (availability only). It cannot repoint a provider's issuer, keys, endpoint, audience or subject mapping: each rule pins the record's identity digest under the offline policy key, so any identity change denies until a re-signed policy is loaded.
- **Stale state.** Each exchange and each admission under a provider-anchored root reads the registry once and matches against that version, as #1535 does for bearer requests. A provider disabled after a root was issued denies the next call under that root, and no cached copy outlives an edit.
- **Unreadable registry.** Startup refuses. At runtime the token endpoint and bearer intake answer HTTP 503 and admission denies. Nothing falls back to a previous copy or to flags.
- **Offline evidence.** The enabled state is admission-time state and is not in any bundle. A verifier recomputes the provider identity digest from the exported projection and checks it against the rule; it does not learn whether the provider was enabled.

### 9.9 Decoding malleability and algorithm confusion

- **Padding.** A member a decoder silently drops is still covered by the signature, so two parties can disagree about a signed artifact's content, and a signer can be induced to sign bytes whose typed reading differs from what it checked. Strict decoding (G18) rejects unknown members at every level, including the serde internally tagged unit-variant gap (T30).
- **Algorithm confusion.** No member of an artifact selects the verifier (G19). The algorithm comes from the pinned, typed key, and the signature encoding prefix must match it. Deleting the unsigned `algorithm` member removes the field an attacker could tamper with, and a document that carries one fails decoding.

## 10. Crate-by-crate changes

Paths are relative to the repository root. "Delete" means in the same PR as the replacement. Milestone in brackets.

### 10.1 `crates/core/chio-core-types`

- `src/crypto.rs` [M0, D16]: `SigningBackend` collapse per the parallel lead's plan: `public_key() -> Result<PublicKey>`; `algorithm()` and `current_public_key()` deleted; the 36 trait impls and the infallible wrappers that call them (kernel `receipt_signing_public_key`, `authority_public_key`, federation `local_public_key` and the others in the plan) become fallible. Byte-neutral, one PR.
- `src/crypto.rs` [M1]: signing-wrapper construction, `sign_wrapped` on the trait and the single verification helper (section 7.0); `sign_canonical_bytes` deleted; algorithm-binding check; verifier selection from the pinned typed key only (G19).
- `src/crypto.rs` [M2]: P-256 and P-384 verification in default builds through the RustCrypto `p256` and `p384` crates (already in the dependency graph as direct dependencies of `chio-mcp-remote`), `no_std` compatible. Under `fips`, the same functions use aws-lc-rs. One public API, one backend per build, and a differential test over shared vectors. `ClassicalSigner` (local `Keypair` or `Arc<dyn SigningBackend>`).
- `src/capability/anchor.rs` (new) [M1]: `RootAnchor`, `AnchorKind`.
- `src/capability/token.rs` [M1]: delete the unsigned `algorithm` member in item 1 (G19), with the receipt's and the other optional `algorithm` members in `chio-core-types` and `chio-credit`; `root_anchor` on `CapabilityTokenBody` and the signing body in item 3. Regenerate `_generated/chio_wire_v1.rs`.
- `src/capability/scope.rs` [M3]: `MonetaryAmount.currency` becomes `asset: Asset`. Every caller changes in the same PR.
- `src/root_authority/` (new) [M1]: `DelegationContext`, `RootPolicy` (anchor and disclosure rules), `EnterpriseProviderIdentity` (the projection and its digest, G17), `IdpKeySnapshot`, `CapabilityPresentation`, `VerifierTrust`, `RevocationRequest` [M2], the pure root-policy matcher, scope projection, the section 7.1 binding checks and disclosure-policy check, `no_std + alloc` compatible so `chio-verify` and wasm verifiers reuse them. Every function takes time as a parameter; none reads a clock. Every type decodes strictly (G18), with a padding negative test per struct and per union variant.
- `src/receipt/decision.rs`, `src/receipt/body.rs` [M1]: commitments, inline fields, `disclosure`, `authority`, the `tenant_id` exclusion; `enforcement` [M2]; `settlement` [M3].
- `src/receipt/kinds.rs` [M1, M2]: delete `RedactionMode` [M1]; add `PdpDecision`, `PreventExternal`, `Delegated` [M2].
- `src/receipt/disclosure.rs` (new) [M1]: `Commitment`, `ReceiptDisclosure`, open and verify.
- `src/receipt/settlement.rs` (new) [M3]: `SettlementBlock`, `SettlementClosure`, `RailRef`.
- `src/signed_artifact.rs` [M1]: register new signed schemas and every existing wrapper id that is not yet registered (G11).
- `src/manifest.rs` [M1]: delete `ToolManifest`, `ToolManifestBody` and `ToolManifest::sign`; chio-manifest `SignedManifest` is the only signed manifest (G9).

### 10.2 `crates/kernel/chio-kernel-core` [M1 unless noted]

- `src/receipts.rs`: the signer takes the parameter and content preimages, draws salts from the host `Rng`, computes both commitments inside its trust boundary, applies the disclosure policy, and returns the signed receipt with its openings. `ContentHashMismatch` becomes `ContentCommitmentMismatch` with the same recompute-before-sign rule. Delete `sign_receipt_relaying_trusted_body`.
- `src/capability_verify.rs`: `AnchoredTrustRoot`, a `TrustRootResolver` that derives the W1.1 trust-root scope hash from the pinned root policy and the delegation context, checks `root_anchor` equality down the chain, the section 7.1 bindings, `expires_at <= assertion_exp`, and exchange-key membership. Depth beyond 0 enabled in M2.
- `chain_digest` helper.

### 10.3 Other receipt producers [M1]

- `crates/kernel/chio-kernel`: receipt assembly fills `authority` from verified capability state only and passes preimages to the core signer. New `DisclosureStore` trait. Guard evidence allowlist before signing. [M2]: `src/receipt_support/signing.rs` `kernel_signing_backend` takes a `ClassicalSigner` so a KMS backend reaches receipt signing (T11); `build_kernel_with_clock` in `chio-control-plane` changes to match. `src/payment.rs` [M3]: delete `X402PaymentAdapter` and its serde aliases; add `X402FacilitatorAdapter` against the pinned `/verify` and `/settle` schemas, `exact` scheme only.
- `crates/kernel/chio-kernel-browser`: relay API takes preimages; `WebCryptoRng` uses `globalThis.crypto`. `sdks/typescript/packages/workers|edge|deno` follow.
- `crates/kernel/chio-kernel-mobile`, `crates/sdk/chio-cpp-kernel-ffi`, `crates/sdk/chio-bindings-ffi`: relay API takes preimages; OS RNG.
- Security producers under `crates/security/` that emit `chio.receipt.v1`: pass the host `Rng` and preimages.
- `sdks/lambda/chio-lambda-extension`: adopt the format or delete the receipt path.
- `crates/platform/chio-http-core`, `chio-api-protect`, `chio-tower` and the HTTP middleware SDKs (Python, JVM, .NET): delete `HttpReceipt`; sign `chio.receipt.v1` through the shared kernel signer with the HTTP request as parameter preimage and the response as content preimage (G4).
- `chio-acp-proxy`, control-plane SCIM and verified-fix producers, and fixture re-signers: pass preimages instead of hashes (G3).
- M0 task (done, #1531): a complete inventory of `chio.receipt.v1` producers, checked in at `docs/superpowers/specs/relying-party-wedge/receipt-producer-inventory.md`. Its gaps are decided in section 2.5.

### 10.4 `crates/trust/chio-signing-remote` [M2]

- `src/aws_kms.rs` (new): `AwsKmsSigningBackend` implementing the collapsed synchronous `SigningBackend`; `public_key()` returns the pinned key after the `GetPublicKey` preflight and errors if the preflight has not succeeded. P-256 (`ECC_NIST_P256`, `ECDSA_SHA_256`, `MessageType=DIGEST` over SHA-256 of the wrapper) and Ed25519 where KMS offers it (pin at build start the key spec and raw signing algorithm names; unverified here). Pins key ARN, region, algorithm and public key in config. Every returned signature is verified locally against the pinned key (existing `sign_bytes_with_identity` guarantee). DER output matches the `p256:<DER hex>` encoding.
- Transport over blocking `ureq` with SigV4, matching the crate's existing pattern, through the HTTP egress contract (`scripts/check-http-egress-contract.sh`). Credentials from environment, ECS/EKS container credentials, IMDSv2 and web identity (Q-B1).
- `RemoteSigningKey` accepts P-256 pins. README "Guarantees" updated.
- Add `crates/trust/chio-signing-remote/` to the clock gate's fixed roots (T25); SigV4 request time reads the injected clock.

### 10.5 `crates/protocol/chio-mcp-remote` [M1, full migration per D1; Entra Agent ID M2]

- `src/remote_mcp/oauth/local_server.rs`: add the `jwt-bearer` grant; replace `exchange_subject_token` and `validate_subject_token` with the anchored exchange for the subject token types in section 7.2, keeping local AS re-exchange as a `chio_local_as` narrowing (T1); add `requested_token_type` handling; confidential client authentication (`private_key_jwt`) for `jwt-bearer` and `token-exchange`. The `authorization_code` flow now yields `chio_local_as` anchored roots.
- `src/remote_mcp/session_core.rs`: `OAuthClientRegistration` gains the client public JWK and `token_endpoint_auth_method`; `JwtHeader` gains `typ` and rejects key-location members and `crit`; claims gain `iat`, `uti` and `resource`; `RemoteAuthMode::StaticBearer` keeps `auth_token` and resolves through the exchange to an `operator_static_bearer` root; per-store path fields replaced by `state_dir`.
- `src/remote_mcp/oauth/root_exchange.rs` (new): verification per anchor kind, replay keys, root policy matching, root minting through the exchange `SigningBackend`, delegation-context, snapshot and tag writes, optional ID-JAG retention [M2], `entra_jwt` [M1], `entra_agent_id` [M2].
- `src/remote_mcp/oauth/bearer_auth.rs` and introspection paths: every bearer intake (static bearer, generic OIDC JWT, introspection, Entra) ends in the exchange and binds an anchored root through the token-digest mapping; no session authority is created any other way. The per-request registry load from #1535 stays and feeds the exchange and the admission provider check (G17).
- `src/remote_mcp/session_identity.rs`: JWKS from the provider record's `jwks_url` or inline `jwks`, refresh on unknown `kid` with rate limit, scheduled refresh, JWKS document checks, snapshot emission; principal and tenant from the record's subject mapping; delete `derive_federated_agent_keypair`, `derive_enterprise_subject_key` (T8), `JwtProviderProfile` and its `AzureAd` fallback chain (G17). The enterprise provider registry stays as the provider identity source.
- `src/remote_mcp/http_service_auth.rs`: AS metadata advertises `urn:ietf:params:oauth:grant-type:jwt-bearer`, the supported token types and `private_key_jwt`.
- `src/remote_mcp/session_core.rs` and `http_service_auth.rs`: delete the configuration fields behind the provider verification flags (`auth_jwt_public_key`, `auth_jwt_discovery_url`, `auth_jwt_issuer`, `auth_jwt_audience`, `auth_introspection_url`, `auth_jwt_provider_profile`); the bearer verifiers are built from provider records per request.
- `src/remote_mcp/session_core/factory.rs`: delete the direct `configure_capability_authority` session issuance path and every remote store branch (`--control-url` admission, receipts, revocations and budgets), with `authority_mode.rs` and the `--control-url` members of the resume fingerprint; the pinned remote trust-control authority becomes the `trust-control` exchange signer, configured apart from any store; sessions receive roots only from the exchange; ephemeral kernel keys refuse startup.
- `src/remote_mcp/admin.rs`: revocation targets from section 7.11 on `/admin/revocations`, always written to the local store; delete its trust-control forwarding and the health members `proxied`, `controlUrl`, `controlTokenConfigured`, `revocationsConfigured` and `budgetsConfigured` [M1]; `POST /v1/revocations` for caller requests [M2].
- State-directory lock at startup (D4).

### 10.6 `crates/protocol/chio-mcp-edge`

- `src/ingress.rs`, `src/runtime/protocol/parsing.rs` [M1]: add `chioCapability` to the closed `_meta` name list and parse it as `chio.capability-presentation.v1` with the same duplicate-key and original-bytes discipline as `_meta.chioDpopProof`.
- Tool result path [M2]: attach `_meta.chioReceipt` (D11).
- x402 MCP transport challenge and payment parsing [M3].

### 10.7 `crates/platform`

- `chio-store-sqlite` [M1]: tables `receipt_openings` and `root_context_openings` (erasable salts), `exchange_replay` (half-open expiry ranges), `anchored_roots` (rule id, subject and tenant tags with their `key_id`, the signed root capability and its delegation context), `bearer_token_roots` (token digest to root), `idp_key_snapshots`, `retained_root_policies`, `retained_provider_identities`, `receipt_tenant_tags`; no tenant index table, since every tag carries its `key_id`; the existing revocation tables gain the section 7.11 target kinds; `idp_artifacts` [M2], `revocation_requests` [M2]. All writes through the existing serving writer, in the database under the state directory.
- `chio-control-plane` trust-control [M1]: `POST /v1/root-exchange/sign` signs an edge-built anchored root or IdP key snapshot. The request is a closed tagged union (`chio.root-exchange-sign-request.v1`): `anchored_root` carries the unsigned capability body, its delegation context and the signed root policy; `idp_key_snapshot` carries a provider record id, the edge's record identity digest and the unsigned snapshot body. It takes typed bodies, never bytes, and typed data alone authorizes nothing. The caller needs a scoped `root-exchange:sign` deployment credential of the deployment the route serves. Before signing a root, trust-control checks it against a root policy signed by its pinned `--root-policy-key`: anchor present, issuer equal to its own key and listed in the policy's `exchange_keys` (so rotating the trust-control key needs a re-signed root policy), rule, scope ceiling, lifetime ceilings and, for provider-backed kinds, the provider identity digest against its registry. Trust-control loads its own enterprise provider registry (the `chio.enterprise-providers.v1` file its provider admin writes, `chio trust serve --enterprise-providers-file`) per request for these checks, and the route refuses when none is configured; a record whose identity digest differs from the edge's refuses, so registry drift fails closed. Before signing a snapshot, it checks that the provider record is enabled in its registry, that the snapshot issuer and source equal the record's (inline keys exactly), and that `exchange_key` is its own key. For a `jwks_url` source it signs the keys the edge observed, so a signed snapshot is the provider's statement, not independent IdP evidence. The response (`chio.root-exchange-sign-response.v1`) echoes the kind and signing schema id. The edge refuses a response of another kind, a body that differs from the one it sent, or a signer outside `--exchange-signer-trusted-public-keys`.
- `chio-control-plane/src/enterprise_federation.rs` [M1]: delete the record member `provider_profile`; add the optional inline `jwks` to `oidc_jwks` records (exactly one of `jwks_url` or `jwks` when referenced by a rule); project a record into `EnterpriseProviderIdentity`. Trust-control's provider admin and its tests change in the same PR (G17).
- `chio-control-plane/src/evidence_export/` [M1]: export writes the new roles, `disclosure_profile` and `tenant_tags`; delete `verification.rs` and the verify half of `evidence_export.rs` once `chio-bundle-verify` replaces them. `build_kernel_with_clock` takes a `ClassicalSigner` [M2].
- `chio-http-core/src/authzen.rs` (new) [M2]: framework-neutral AuthZEN types, mapping to Chio evaluation, PEP allowlist type.
- `chio-manifest` [M3]: tool `pricing` block.

### 10.8 `crates/products`

- `chio-cli` [M1]: `serve-http --root-policy`, `--root-policy-key`, `--exchange-signer`, `--kernel-signer` (value `seed-file:<path>` in M1, `--exchange-signer` also `trust-control:<url>` with `--exchange-signer-credential-file` (a scoped trust-control caller credential) and `--exchange-signer-trusted-public-keys` (the rotating set of keys trust-control may sign roots with); `aws-kms:<arn>` added in M2), `--tenant-index-keys <dir>`, `--state-dir`; `--control-url` and `--control-token` refused for `serve-http`; `--auth-token` and `--enterprise-providers-file` kept (sections 7.2, 7.4); the per-store database path flags, `--auth-jwt-provider-profile`, `--auth-jwt-public-key`, `--auth-jwt-discovery-url`, `--auth-jwt-issuer`, `--auth-jwt-audience` and `--auth-introspection-url` deleted (G17). The operator runbook and examples move their provider settings into registry records. The progressive tutorial, conformance peers, examples, deploy units and SDK publication scripts gain a root policy file and move to `--state-dir` in the same PR. `chio evidence verify` delegates to `chio-bundle-verify`. `chio evidence export --edge-url --disclosure-profile --tenant-issuer --tenant-value` (the M1 item 6 plan). `chio trust serve --root-policy-key` and `--enterprise-providers-file` for the root exchange sign route. `chio mcp root-request sign --operator-seed-file` for signed operator root requests. `chio revoke` admin subcommands.
- `chio-api-protect` [M1]: committed receipts through the shared kernel signer (no root policy, no inline fields). [M3]: anchored roots, root policy and disclosure, tenant index and export, x402 HTTP 402 challenge, the section 8.3 startup refusals.

### 10.9 New crates

- `crates/tooling/chio-bundle-verify` [M1] (library plus `[[bin]] chio-verify`, Apache-2.0): reads a bundle and a `chio.verifier-trust.v1` file, verifies everything offline, prints the column report (section 11.4). Depends on `chio-core-types` and `chio-kernel-core`; no tokio, no rusqlite, no network except the optional `--online` settlement lookup behind a feature [M3]. It never reads the wall clock: expiry and validity checks evaluate at the receipt's own timestamp. Added to the clock gate's fixed roots.
- `crates/guards/chio-cedar-guard` (optional, F6, not a milestone deliverable).

### 10.10 SDK verifiers, spec and docs

- `sdks/typescript`, `sdks/python`, `sdks/go` verifiers [M1]: signing wrapper, commitments, openings, strict decoding of every section 7 type (G18), algorithm from the pinned key only (G19), new vectors. These change in the same PRs as the Rust format change. Default-build P-256 verification in the SDKs [M2].
- `spec/PROTOCOL.md` [M0]: section 4 (signing wrapper, algorithm binding); new subsection 5.6 "Anchored roots and the relying-party exchange"; section 6 table and WYSIWYS text for commitments, the `tenant_id` exclusion and producer salt sources; 6.1 for `pdp_decision`; new 6.7 "Settlement block and closure"; 8.2 updated once the ADR is accepted; 10.3 rewritten so the enterprise provider registry is the one source of provider identity and root policy rules reference records by id and identity digest (G17); the section 14 gap line on enterprise identity propagation narrowed to "outside exchange-issued roots"; a deployment-limits note for single-instance edges. `spec/WIRE_PROTOCOL.md` [M0]: `_meta.chioCapability` and `_meta.chioReceipt`.
- `spec/schemas/chio-wire/v1/` [M0]: schemas for every artifact in section 7, including the optional ID-JAG retention slot (D7), the M2 and M3 artifacts and `chio.enterprise-provider-identity.v1`; every object `additionalProperties: false` and every tagged union a `oneOf` of closed objects (G18); `registry.json` entries.
- `docs/adr/` [M0]: the customer-hosted root exchange ADR outlined in section 15 (`docs/adr/ADR-0039-customer-hosted-root-exchange.md`, #1533), accepted before M1 code merges (T22, D12).
- `docs/reference/CLAIM_REGISTRY.md`: one row per acceptance statement in section 12, added only when its evidence exists.
- `docs/release/QUALIFICATION.md` [M1]: the hosted authorization edge rows (including the row whose command runs `mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange`, which exercises local AS re-exchange) are marked suspended at the M1 migration merge and rewritten against the anchored flow when the lane re-passes (D1).
- `README.md` and public docs [M1]: state the hosted-edge qualified-label suspension from the M1 migration merge until the lane re-passes, and remove the statement when it does (F13).

## 11. Test plan

### 11.1 Unit and property tests

- Signing wrapper: every registered signed artifact type signs and verifies through the one helper; an artifact with an added or altered `algorithm` member fails strict decoding, and the verifier chosen for a pinned key is the same with and without such a member (G19); a signature over one schema id fails as another; the verifier ignores any schema member inside the artifact and uses its call-site schema id; a signature prefix that does not match the pinned key's algorithm rejects; a stripped hybrid signature fails against a pinned hybrid key; ML-DSA-65 with a non-empty context fails; Ed25519, P-256 (both backends, M2 for default builds), P-384 and hybrid vectors.
- Trait collapse [M0]: every changed crate suite green with no byte change in any fixture (fixture digests compared before and after).
- Client authentication: public client on `jwt-bearer` denies; missing, expired, wrong-`aud`, wrong-key and replayed client assertions deny.
- Anchor verification per kind: valid, expired, future `iat`, wrong `aud`, wrong `typ`, wrong `resource`, unknown `kid`, rotated key, `alg` outside `allowed_algs`, HMAC `alg`, `jku`/`x5u`/`jwk`/`x5c`/`crit` headers, JWKS key with `use: enc`, RSA modulus below 2048 bits, oversized JWKS, ID-JAG lifetime above the cap, computed `expires_at <= now`, replayed `jti` (including after restart against SQLite), the same `jti` under two issuers (both accepted), NUL in issuer or subject, Entra issuer on an `oidc_jwt` rule's provider record rejects at load; `entra_jwt`: multi-tenant issuer, principal from the record's `principal_source` (`oid`), a token without that claim denies, reused `uti`, a second token with a bound `uti`, root lifetime `min(ttl, token exp)`. M2: agent-identity token routed to `entra_agent_id` and denied by an `entra_jwt`-only policy, token without the discriminator denied by an `entra_agent_id`-only policy.
- Provider registry (G17): a rule naming a missing record, a record of the wrong kind, an invalid record or a record whose identity digest differs refuses startup; a provider-backed rule without `--enterprise-providers-file` refuses startup; a provider disabled or removed after a root was issued denies the next exchange and the next call under the live root; re-enabling it admits again; an unreadable or corrupted registry answers HTTP 503 at the token endpoint and bearer intake and denies admission; a record whose `jwks_url` changes without a re-signed policy denies; one request reads the registry once; the exchange never follows `discovery_url`; an inline `jwks` record verifies tokens and writes a `registry:<provider_id>` snapshot.
- Strict decoding (G18): for every section 7 type, one added member at each nesting level fails decoding even when the signature over the padded body is valid; for every tagged union, `{"kind":<variant>,"pad":0}` fails; a type using `#[serde(flatten)]` fails a repository check.
- Schema-only rejections [M1]: for each section 7 type, the hand-written decoder or load check rejects every invalid example under `spec/schemas/chio-wire/v1/root_authority/examples/invalid/`, including the examples the generated bindings accept (`const`, `maximum`, item-count bounds and the kind conditionals). The list is in `docs/superpowers/specs/relying-party-wedge/in-place-schemas/README.md` and pinned by `crates/core/chio-core-types/tests/root_authority_generated_examples.rs`.
- Bearer intake: the same token in two sessions maps to one root; a different token with the same `(iss, sub, iat, exp)` and no `jti` gets its own root.
- Static bearer: `--auth-token` without an `operator_static_bearer` rule refuses startup; a rule without `principal` refuses startup; a wrong token denies; the root names the configured principal and the receipt's identity column verifies as `asserted`; the token never appears in the state directory or logs; a new root is minted after expiry.
- Local AS re-exchange: narrowed scope and `resource` succeed; widening, an expired or revoked subject token, and a second re-exchange of the same token deny.
- Trust-control exchange signer: a root and a snapshot signed through a trust-control stub verify under a key in the trusted set, including after the set rotates; a signature outside the set, a cross-kind or substituted-body response and an unreachable stub fail the mint.
- Root lifetime: `expires_at == min(now + ttl, assertion exp)` for every kind; a root with `expires_at > assertion_exp` denies.
- Root binding: issuer key differs from `exchange_key`; scope hash differs from `effective_root_scope_hash`; `assertion_exp` differs from `token_exp`; `edge_session` root with a sender key; each denies.
- Root policy: zero, one and two matching rules; projection removes and never adds (proptest: for random IdP scopes, effective scope is a subset of the ceiling); unknown scope value denies; disclosure pointers parse and reject malformed input; `policy_key` mismatch with the pinned key refuses startup; policy outside its validity window refuses startup and denies at runtime.
- Commitments: opening round trip; one-bit change in salt, payload or domain rejects; a subject opening presented as a tenant opening rejects; salts differ across receipts for identical arguments; property test that, for arguments and results built from random 16-byte marker values, no marker (raw, hex or base64) appears in the canonical signed body, guard evidence, metadata or OCSF output outside inline fields, across all guard evidence producers; per-chunk stream digests never appear in signed fields; inline field not in policy fails signing [M2]; `tenant_id` with `authority` fails signing.
- Producers: each producer in the M0 inventory emits committed receipts that the Rust, TS, Python and Go verifiers accept; the WASM build signs in a Miniflare test with a salt drawn from `globalThis.crypto` (closing the existing Workers RNG failure).
- Revocation: each target kind denies the next call; cascade to descendants; store error denies; subject and tenant revocations store only tags; a revocation acknowledged while a concurrent admission is pending is seen by every admission that commits after the acknowledgement; caller revocation request accepted only for strict descendants [M2].
- Single instance: a second process on the same state directory refuses to start; after `kill -9` of the first, a new process starts; a network-filesystem state directory refuses.
- Keys: equal exchange and kernel seeds refuse startup; local AS key equal to the exchange key refuses; a group-readable seed file refuses.
- KMS backend against a local stub HTTP server [M2]: success, throttle, timeout, wrong-key signature, malformed DER, public-key mismatch at preflight, `public_key()` before preflight errors.
- Tenant export: a `caller` bundle contains only the tenant's receipts and only that tenant's salts; auditor profiles never contain salt-only openings.
- AuthZEN mapping [M2]: unlisted PEP, missing presentation, spend-bearing grant denial, enum coherence for `pdp_decision`, PEP opening carries only the params salt.
- x402 [M3]: price above cap denies without challenge; asset mismatch; payload amount mismatch; `payTo` mismatch; mainnet chain id rejects at manifest load; `/settle` timeout yields `authorized_pending` and exactly one closure.

### 11.2 Conformance vectors

- `tests/bindings/vectors/signing/` [M0]: signing-wrapper vectors for each registered schema id and algorithm, including negative vectors for schema-id substitution and algorithm-prefix mismatch, generated in M0 by a small reference script (Python standard library plus a pinned Ed25519 and ECDSA library) and cross-checked by the Rust implementation in M1. M1 item 1 adds algorithm negatives (G19): a capability and a receipt with an added top-level `algorithm` member, and with `algorithm` altered to name another algorithm, each fail strict decoding; and a P-256 pinned key with an `algorithm: "ed25519"` member and an Ed25519 signature still rejects on the encoding prefix.
- `tests/bindings/vectors/receipt/` [M0, M1]: committed receipts with openings, inline fields with a referenced policy [M2], `pdp_decision` receipts [M2], settlement blocks and closures [M3]. TS, Python and Go verifiers run them. Padding negatives (G18), each with a valid signature over the padded body: an added member in a commitment, `disclosure`, `authority`, `authority.root_anchor`, the opening document and one opening [M1]; in `enforcement` [M2]; in `settlement`, one `rail_refs` entry and the closure [M3].
- `tests/bindings/vectors/capability/` [M1, M2]: anchored roots per M1 kind (including `operator_static_bearer` and `entra_jwt`), negative vectors for each section 8.2 rule; padding negatives (G18) for `root_anchor`, the delegation context (`anchor`, `exchange`, a commitment, `claims`), the presentation envelope, the root policy (rule, `match`, `disclosure.tools` entry), an IdP key snapshot key and the provider identity projection; Entra Agent ID roots [M2]; chains of depth 1, 2 and 4 [M2]; a padded revocation request [M2].

### 11.3 Verdict-matrix additions

New categories under `crates/tooling/chio-conformance/verdict_matrix/scenarios/`, with `manifest.toml` counts and index hash re-pinned at each addition:

| Category | Milestone | Covers |
|---|---|---|
| `anchored_root` | M1 (24), M2 (+4) | each M1 anchor kind allow, including static bearer and `entra_jwt`; section 8.1 and 8.2 denies (client authentication, replay, missing anchor, lifetime, unlisted exchange key, Entra issuer on an `oidc_jwt` rule); `entra_jwt` multi-tenant issuer and `uti` reuse after root expiry; provider registry (provider disabled after the root was issued, provider removed, registry unreadable at exchange and at admission, provider identity changed without a re-signed policy); strict decoding (padded `root_anchor`, added `algorithm` member, padded root policy at load). All 24 are staged in M0 (section 2.5). M2 adds Entra Agent ID allow, discriminator routing in both directions, and agent `uti` reuse |
| `receipt_disclosure` | M1 (12) | committed default; evidence allowlist drop; `tenant_id` exclusion; salt-only opening rejected in auditor profile; inline-field scenarios written in M1 as expected-deny at policy load and flipped in M2 |
| `revocation_local` | M1 (14) | each provider revocation target denies the next call; cascade; concurrent revocation and admission |
| `delegation_chain` | M2 (12) | depth 1-4 allow; reorder, gap, widened hop, mismatched anchor deny; offline verify equals online verdict; caller revocation of a descendant |
| `pdp_decision` | M2 (12) | allow and deny with signed receipt; unlisted PEP; spend-bearing grant denied |
| `x402_challenge` | M3 (12) | challenge issued; paid call allowed; over-cap and asset-mismatch denied before challenge; settle timeout to closure; same scenarios through `api protect` |

`category` in `SCENARIOS.md` gains the six values. Existing scenarios that assert `parameter_hash` or `content_hash` are rewritten for commitments in M1. `rust-kernel` stays the required driver. A new driver `rust-mcp-serve-http` runs the M1, M2 and M3 categories through a real `serve-http` process with a local IdP stub (JWKS server minting ID-JAG and Entra-shaped tokens, and Entra agent-identity tokens from M2, with fixed timestamps, plus a registered confidential client key) and a local facilitator stub.

### 11.4 `chio-verify` column report tests

For each column, a bundle that yields each evidence class (`verified`, `observed`, `asserted`, `unverifiable`, `rejected`), and the exit status for `required_columns`.

| Column | `verified` when | Otherwise |
|---|---|---|
| identity root | exchange key pinned, root signature valid, root policy key pinned, policy matches the recorded claims, `context_digest` recomputes, section 7.1 bindings hold, and (M2) the retained ID-JAG verifies against a key pinned in the verifier's `idp_keys` | `observed` when the retained ID-JAG verifies only against the provider-signed snapshot; `asserted` for bearer anchors without a retained artifact; `rejected` on any mismatch |
| delegation chain | every hop verified from the presentation with W1.1 and W1.2; no revocation entry in the bundle covers it | `rejected` |
| decision | kernel key pinned, signature valid, kind coherent; `pdp_decision` only with a pinned PEP key | `observed` for `pdp_decision` without a pinned PEP |
| content | commitment opened from the bundle and matches; every inline field authorized by the included root policy | `unverifiable` in `auditor_hash_only`; `rejected` on mismatch or unauthorized inline field |
| settlement (M3) | inline settlement with matching digests, or exactly one valid closure; `--online` confirms the transaction | `asserted` without `--online` |

### 11.5 Clock gate and repository gates

- `scripts/check-security-clocks.py` passes with no new inventory entries in `chio-mcp-remote`, `chio-mcp-edge`, `crates/kernel/`, `chio-control-plane` and `chio-store-sqlite`. Token time checks, client assertion lifetime, replay expiry, JWKS refresh scheduling, policy validity, revocation request skew checks and (M2) SigV4 request time all read the injected clock. `crates/tooling/chio-bundle-verify/` [M1] and `crates/trust/chio-signing-remote/` [M2] are added to the fixed roots (T25).
- Fixtures use fixed finite timestamps (for example `issued_at = 1792234800`), never `SystemTime::now()`.
- `scripts/check-chio-schema-registry.sh`, `scripts/check-wire-schemas.py`, `scripts/check-error-urn-registry.py` (every new `urn:chio:error:*` reason), `scripts/check-receipt-trace-negative-registry.py` (negative entries for the new kind and boundary class), `scripts/check-http-egress-contract.sh` (JWKS, KMS, facilitator clients), `scripts/check-adapter-no-bypass.sh`, and the claim-registry integrity test.
- Signed fixtures across the repository (export bundles, conformance snapshots, binding vectors) are regenerated for the signing wrapper and commitments in M1, after coordination with the parallel lead (D17). The builder lists every regenerated fixture in the PR description.
- The full workspace one-liner from `CLAUDE.md` at the final tip of each milestone, run on the build workstation.

### 11.6 Live tests (manual, recorded)

- Okta developer tenant with Cross App Access (pin plan availability at build start) issuing a real ID-JAG to a real MCP client, registered as a confidential client, against a staged `serve-http` [M1].
- The hosted-edge qualification lane re-run on the migrated `serve-http` [M1].
- A second person on a separate machine with no network runs `chio-verify` on an exported `caller` bundle and an `auditor_hash_only` bundle [M1].
- Entra test tenant with an ordinary application token calling the staged edge [M1].
- Entra test tenant with an agent identity calling the staged edge [M2].
- AWS KMS P-256 and Ed25519 keys in one region; latency and quota measurements [M2].
- x402 on Base Sepolia with a public testnet facilitator [M3]; no mainnet.

## 12. Acceptance criteria per milestone

Each milestone lists what may be said once its evidence exists, and what may not. A statement enters `CLAIM_REGISTRY.md` only with its evidence.

### M0: decisions and contracts

Preconditions (D17): M0 code starts after #1496 and #1489 land. Every PR in M0 or later that changes `chio.receipt.v1` or capability signing bytes is coordinated with the parallel lead before it opens.

Exit: ADR accepted (section 15); PROTOCOL and WIRE_PROTOCOL text for the signing wrapper, committed receipts, producer salt sources, anchored roots and deployment limits merged; JSON schemas for every artifact in section 7 merged, including the optional ID-JAG retention slot; signing-wrapper and committed-receipt conformance vectors merged from the reference script; producer inventory checked in; verdict-matrix scenario files for the three M1 categories written (expected to fail); the `SigningBackend` collapse merged byte-neutral (D16).

May say: nothing externally.

### M1: ID-JAG and Entra intake, full migration, committed receipts, local revocation, verifier

Evidence: section 11 tests for M1 green on `main`; the three M1 verdict-matrix categories pass in `rust-kernel` and `rust-mcp-serve-http`; every SDK verifier passes the new vectors; live Okta and Entra runs recorded; the conformance peers pass against the migrated edge with `--auth-token`; the hosted-edge qualification lane re-passes on the migrated `serve-http`.

May say (shipped; `serve-http` qualified again only after the lane re-passes):

- "`chio mcp serve-http` accepts Okta Cross App Access ID-JAG assertions from authenticated clients, verifies them against the IdP's published keys, and roots every capability it issues in an exchange recorded under a provider-signed root policy."
- "`chio mcp serve-http` accepts Microsoft Entra access tokens from tenant-specific issuers and roots each one in an exchange recorded under the provider's root policy. Disabling an Entra principal takes effect at the provider when its already-issued tokens expire, typically about one hour."
- "For Okta ID-JAG principals, disabling the principal at the IdP takes effect at the provider within 300 seconds plus the configured clock skew (at most 60 seconds), by default."
- "The provider can revoke a capability, a principal, a policy rule or a tenant. Every call admitted after the revocation is recorded denies."
- "Disabling or removing an identity provider in the provider registry denies the next exchange and the next call under capabilities rooted in it."
- "Every Chio receipt contains salted commitments to tool arguments and results instead of plaintext."
- "A provider can export a bundle for one customer tenant that the tenant verifies offline with the Apache-2.0 `chio-verify` tool."

May not say: "any IdP"; anything about Entra Agent ID; "real-time Entra revocation"; static bearer as production identity or as IdP-backed; "IdP-verified receipts"; "multi-hop offline verification"; "real-time revocation"; "highly available" or any multi-instance wording; "zero-knowledge" or "anonymous"; "KMS", "HSM-backed", "keys the process never holds" or any custody or host-compromise wording; "each tool response carries a receipt"; plaintext or inline disclosure wording; anything about `chio api protect` beyond committed receipts.

### M2: Entra Agent ID, KMS, caller copy, AuthZEN, OCSF, portable chains, caller revocation, deferred M1 items

Evidence: Entra Agent ID additions to `anchored_root`, `delegation_chain` and `pdp_decision` categories pass; live Entra Agent ID and KMS runs recorded; OCSF output validated against the pinned 1.9.0 schema; a depth-4 chain bundle verifies on an offline machine with the same verdict as the online edge; caller revocation exercised; caller copy, inline disclosure, `auditor_full` export and ID-JAG retention tests green.

May say (shipped):

- "`chio mcp serve-http` also accepts Microsoft Entra Agent ID agent-identity tokens. Disabling an Entra principal takes effect at the provider when the agent's already-issued tokens expire, typically about one hour."
- "Receipts and capabilities can be signed by an AWS KMS key that the Chio process never holds."
- "Each tool response carries the caller's own signed receipt and the material to open it."
- "Plaintext appears in a receipt only for fields the provider's signed policy names."
- "`chio mcp serve-http` serves the OpenID AuthZEN 1.0 evaluation API. Each decision is returned with a signed receipt that names the enforcement point that asked."
- "Chio exports receipts as OCSF 1.9 API Activity events carrying the delegation chain and a reference to the signed receipt."
- "Delegation chains of any depth rooted in an exchange-issued capability verify offline from an exported bundle." The approved "single-hop portable" wording is replaced only after the claim review accepts this evidence.
- "A calling organization can revoke capabilities it delegated by sending the provider a signed revocation request."
- "When the provider opts in and the auditor pins the IdP's keys, an auditor can verify the Okta ID-JAG behind a capability offline."

May not say: "real-time Entra revocation"; "Chio enforces calls through AuthZEN" (it decides; the PEP enforces); "Chio speaks Cedar"; "OCSF events are signed" (they reference signed receipts); AuthZEN on `api protect`; "HSM-backed" beyond the KMS key itself.

### M3: paid tools and `api protect`

Evidence: `x402_challenge` category passes through both `serve-http` and `api protect`; live Base Sepolia run recorded; closure path exercised by a forced facilitator timeout; `api protect` passes the M1 categories with anchored roots.

May say (shipped, testnet):

- "For tools priced in the signed manifest, Chio answers unpaid calls with an x402 payment challenge, runs the tool only after the facilitator reports settlement to the provider's address, and binds the settlement reference into the receipt. Exercised on testnet only."
- "`chio api protect` accepts the same exchange-issued roots and root policies as `serve-http`."

May not say: "x402 support" without "testnet"; "Chio processes payments"; "refunds"; mainnet anything; "Chio holds funds" or any custody wording.

## 13. Milestones, sizes and ordering for one engineer

Sizes are engineer-days. S is 5 or fewer, M is 6 to 15, L is more than 15; a range that straddles a boundary takes the larger label. Staffing (D10): one engineer plus coding agents. Agents write code and tests; the engineer reviews, integrates, runs heavy builds and owns live runs. The sizes count the engineer's days, with agent assistance already assumed.

### 13.1 Cuts applied from day one of M1

These are out of M1 before M1 starts. Each is scheduled in M2.

1. Policy-authorized inline disclosure (tool and field). M1 receipts are fully committed everywhere; the root policy schema carries the `disclosure` slot from M0, and M1 rejects any non-empty `tools` map at load.
2. All AWS KMS signing, P-256 and Ed25519, together with `ClassicalSigner` plumbing and default-build P-256 verification in Rust and the SDKs (F11). M1 signs with seed-file Ed25519 keys only and makes no custody claim.
3. The `auditor_full` export profile. M1 ships `caller` and `auditor_hash_only`.
4. ID-JAG retention (D7). The schema slot exists from M0; M1 rejects `retain_idp_artifact: true` at load.
5. Presented chains deeper than the root (section 6.4).
6. Caller-side revocation requests (D3).
7. The caller copy in `_meta.chioReceipt` (F11). In M1 callers rely on `caller` bundles.
8. Entra Agent ID intake (F11). `entra_agent_id` rules reject at load in M1; ordinary Entra tokens use `entra_jwt`.

Not available as cuts: the `operator_static_bearer`, `oidc_jwt`, `oauth_introspection`, `entra_jwt`, `chio_local_as` and `chio_operator_key` kinds and the trust-control exchange signer (D1 and F14 require every kept auth path to migrate in M1), confidential client authentication for ID-JAG (without it a stolen ID-JAG is redeemable by anyone who knows the `client_id`), protocol-wide commitments (D2), and the signing wrapper (D6).

### 13.2 Sizes

| Milestone | Item | Size |
|---|---|---|
| M0 | ADR; PROTOCOL and WIRE_PROTOCOL text; all section 7 schemas; producer inventory; scenario files | M, 8-10 |
| M0 | Signing-wrapper and committed-receipt reference script and vectors | S, 4-5 |
| M0 | `SigningBackend` collapse (D16): trait, 36 impls, fallible wrappers, about 1.5k-2.5k changed lines, byte-neutral | M, 5-7 |
| M0 total | | 17-22 |
| M1 | 1. Signing wrapper in `chio-core-types` (`sign_wrapped`, algorithm binding), all signing call sites including the raw-site table, registration of every unregistered wrapper id with its schema, the schema-id binding signer, deletion of the core-types `ToolManifest`, deletion of the unsigned `algorithm` members with algorithm negatives (G19), Rust and SDK verifiers, fixture regeneration | L, 23-32 |
| M1 | 2. Committed receipts in every producer (kernel-core signer, hosted kernel, `api protect`, FFI, WASM, mobile, security producers, Lambda extension), `HttpReceipt` deletion with the HTTP middleware SDKs, preimage plumbing for hash-relaying producers, `tenant_id` exclusion, guard evidence allowlist, disclosure store, SDK verifiers, scenario and fixture rewrites | L, 26-37 |
| M1 | 3. Anchored-root types with strict decoding and padding negatives (G18), section 7.1 bindings and `AnchoredTrustRoot` (depth 0) | M, 7-9 |
| M1 | 4. Exchange: ID-JAG with confidential client authentication; the kept kinds (`operator_static_bearer`, `oidc_jwt`, `oauth_introspection`, `entra_jwt`, `chio_local_as` with re-exchange, `chio_operator_key`); trust-control exchange signer; the provider registry as the provider identity source (identity projection and digest, per-request reads at exchange and admission, record changes in trust-control, registry scenarios, G17); deletions (seed-derived keys, bypass issuance, provider profile and provider verification flags, per-store path flags) with tutorial, peer, example, runbook and deploy updates; pinned JWKS with refresh and snapshots; replay keys; tenant and subject tags; state-directory lock | L, 27-38 |
| M1 | 5. Revocation target kinds on the existing store, linearized with admission, provider revocation admin | M, 4-6 |
| M1 | 6. `chio-bundle-verify` (including the provider identity role), `caller` and `auditor_hash_only` export | M, 7-11 |
| M1 | 7. Tests, vectors, `rust-mcp-serve-http` driver, live Okta and Entra runs, conformance peers on the migrated edge, hosted-edge qualification lane re-run, QUALIFICATION and README updates | M, 10-15 |
| M1 total | | 104-148 |
| M2 | Entra Agent ID intake beside `entra_jwt` (D5, D14), discriminator routing and live run | S, 3-5 |
| M2 | `ClassicalSigner` plumbing, default-build P-256 verification (Rust and SDKs), AWS KMS P-256 backend, live KMS run | M, 10-13 |
| M2 | KMS Ed25519 | S, 3-4 |
| M2 | Caller copy in `_meta.chioReceipt` | S, 2-3 |
| M2 | Inline disclosure policy (tool and field) | M, 6-8 |
| M2 | `auditor_full` export and ID-JAG retention | M, 6-8 |
| M2 | Portable chain presentation (depth 1+), verifier chain column | M, 8-12 |
| M2 | Caller-side revocation requests | M, 6-8 |
| M2 | AuthZEN endpoints on `serve-http`, `pdp_decision` class, PEP allowlist | M, 8-12 |
| M2 | OCSF 1.9 projection | S, 3-5 |
| M2 total | | 55-78 |
| M3 | `api protect`: anchored roots, root policy and disclosure, tenant index and export, startup refusals | M, 10-14 |
| M3 | Typed `Asset` (in place, all callers), manifest pricing, facilitator adapter, x402 challenge on MCP and HTTP, settlement block and closure | L, 18-25 |
| M3 total | | 28-39 |

M1 is 104-148 engineer-days after the day-one and second-line cuts and the section 2.5 decisions (100-141 before G17 to G19, 87-122 before G1 to G16). At about 21 working days a month that is roughly five to seven months for one engineer, before any wait for the D17 byte-change coordination. The M1 window in the private schedule is set against this number.

### 13.3 M1 order for one engineer

Ordered so each step lands on `main` green and later steps build on it:

1. Signing wrapper (item 1), on the collapsed trait from M0. It touches every signed fixture, so it goes first while the tree is otherwise stable. Its PR opens only after the D17 coordination.
2. Committed receipts (item 2) in one squash-merged PR that changes the format, every producer and every verifier. Commits follow the inventory's commit groups, with each producer's salt-source wiring in its own commit (G1). Same D17 coordination.
3. Anchored-root types and resolver (item 3).
4. Exchange and migration (item 4): ID-JAG with client authentication first, then the kept auth kinds and the trust-control signer, then the deletions in the final PR of the step.
5. Revocation (item 5), after reconciling the store shape with coop2c (section 7.11).
6. Verifier and export (item 6).
7. Qualification lane re-run and live run (item 7), with unit and vector tests landing inside each earlier step.

### 13.4 Further cuts if M1 still slips

No further cut is pre-approved. Any cut below removes an M1 deliverable and needs the founder's approval:

1. The `auditor_hash_only` export profile moves to M2. M1 ships only `caller` bundles.

## 14. Open questions

### 14.1 For the founder

- **Q-F12 Static bearer and generic Entra in M1.** Decided 2026-10-17 (founder): keep useful paths; no compat hacks. Both are kept and mapped onto anchored roots in M1: `--auth-token` as `operator_static_bearer` (dev, test and conformance; operator-attested identity; no IdP evidence) and generic Entra as `entra_jwt` under the D5 rules. Entra Agent ID is added in M2 beside `entra_jwt`.

### 14.2 For the builder

- **Q-B1 KMS client implementation (M2).** Hand-rolled SigV4 over `ureq` with a minimal credential chain (consistent with `chio-signing-remote`), or `aws-sdk-kms` on a dedicated runtime thread behind the synchronous trait (calling `block_on` from inside the kernel's tokio runtime panics). Decide by binary size, supply-chain review and credential-source coverage.
- **Q-B2 Receipt economic blocks.** Whether to fold `financial`, `economic_authorization` and `governed_transaction.metered_billing` into the new `settlement` block in M3 or add `settlement` only for x402. Folding is the house-rule direction; size it before M3 starts.
- **Q-B3 RFC 9449 `jkt`.** Adding standard DPoP `cnf.jkt` as a closed confirmation profile would let third-party MCP clients hold caller-held roots. It is interop with an external standard and allowed by the house rule; decide if a design partner needs it.
- **Q-B4 JWKS refresh intervals.** Pick the unknown-`kid` refresh rate limit and the scheduled refresh period within the bounds in section 9.2, and the JWKS size cap.
- **Q-B5 Disclosure-store loss.** Confirm the section 8.4 choice (receipt appended, opening marked lost) against durable admission ordering; the alternative is to deny when the opening cannot be stored first.
- **Q-B6 OCSF and x402 pins.** Record the exact OCSF 1.9.0 attribute names and the x402 MCP transport shape on day one of M2 and M3.
- **Q-B7 Facilitator choice for tests.** Which public testnet facilitator the live run uses, and whether a local facilitator stub is enough for CI.
- **Q-B8 Testnet allowlist.** The exact CAIP-2 ids in the compiled-in rehearsal allowlist.
- **Q-B9 ID-JAG draft revision and client authentication.** Which draft revision to pin if the IETF draft moves before M1 ships, whether the stable MCP profile references a fixed revision, and which token endpoint client authentication method the stable profile requires (section 6.2 step 2).
- **Q-B10 Tenant index key custody.** Whether the tenant index key should later move to a KMS HMAC key, given that per-receipt KMS calls would add latency and quota pressure.
- **Q-B11 Network filesystem detection.** How the state-directory check detects network filesystems on Linux and macOS (section 6.1).

## 15. ADR outline: customer-hosted root exchange (D12)

Written as `docs/adr/ADR-0039-customer-hosted-root-exchange.md` in M0 (#1533). ADR-0038 reserves 0023 to 0037.

1. **Context.** PROTOCOL 8.2 blocks hosted OAuth authorization-server product work pending an ADR. The relying-party wedge needs the local AS in `serve-http` to accept external IdP assertions and issue anchored Chio roots. Today the local AS exchanges only its own tokens (T1) and every registered client is public (T26).
2. **Decision.** The provider runs the root exchange inside its own `serve-http` process, on the existing local AS, using provider-controlled exchange and policy keys. Backbay operates no exchange in v1. Every `serve-http` root is exchange-issued and anchored, including roots for the static bearer, generic OIDC, introspection, Entra and local AS paths; session issuance that bypasses the exchange is removed. The exchange signer is a local seed file or the pinned remote trust-control authority.
3. **Scope.** Grants: `authorization_code` (local users, `chio_local_as`), `jwt-bearer` (ID-JAG), `token-exchange` (ID-JAG and Entra, capability out; local AS re-exchange, narrowing only). `jwt-bearer` and `token-exchange` with an external subject token require confidential client authentication (`private_key_jwt`, or the method the stable MCP profile requires). Bearer intake for the static bearer, generic OIDC JWT, introspection and Entra ends in the same exchange. No refresh tokens. No dynamic client registration beyond the existing startup registry.
4. **Security properties.** Fail-closed rules from section 8.1; single-use replay keys namespaced by issuer; keys only from the provider record a rule references and pins by identity digest; IdP never consulted after the root; root lifetime capped by assertion `exp`; exchange, kernel, policy and local AS keys distinct; policy key pinned in configuration; single instance per state directory.
5. **Standards pinned.** RFC 6749, RFC 7523 (grant and client authentication), RFC 8693, RFC 8707, RFC 9728 metadata, MCP Enterprise-Managed Authorization (stable profile) and the ID-JAG draft revision recorded at build start.
6. **Consequences.** PROTOCOL 8.2 unblocked for this scope only; the hosted-edge qualification lane re-runs in M1 and the label is suspended, publicly, until it passes; seed-derived federation keys, bypass issuance, the provider-profile flag and the provider verification flags are deleted, and the enterprise provider registry is the one source of provider identity that root policy rules reference by id and identity digest; the static bearer is documented as a development, test and conformance mode with operator-attested identity; a Backbay-hosted exchange requires a new ADR.
7. **Alternatives rejected.** Trust-control as the exchange (a second deployable for every provider); self-anchored roots at the edge (excluded by F3); keeping direct issuance beside the exchange (excluded by D1 and the no-compat rule); public clients on the assertion grants (a stolen assertion would be redeemable by anyone knowing the `client_id`).
