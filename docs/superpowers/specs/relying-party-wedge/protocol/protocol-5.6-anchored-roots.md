<!--
Target: spec/PROTOCOL.md
Insertion point: new subsection after "### 5.5 Verified Core Boundary", before "## 6. Receipt Contract".
Move the text below this comment into place unchanged; drop this comment.
-->

### 5.6 Anchored Roots And The Relying-Party Exchange

Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Sections in force until then: 5 (capability contract without `root_anchor`), 8.2, 8.3, 10.3 and "Inbound sender authority profile".

The decision record is
[ADR-0039](../docs/adr/ADR-0039-customer-hosted-root-exchange.md). A provider
runs the root exchange inside its own `chio mcp serve-http` process. Every root
capability that `serve-http` admits is signed by a pinned exchange key and
carries a `root_anchor`.

Encodings: public keys use the self-describing forms of section 4.4 (bare
64-hex Ed25519, `p256:`, `p384:`, `hybrid:`). Digests are
`sha256:<64 lowercase hex>`. Timestamps are Unix seconds. Domain-separation
prefixes end in a NUL byte. Every string that feeds a NUL-delimited hash or
HMAC input (issuers, subjects, tenant values, claim names) is rejected at
intake if it contains a NUL character. Example values below are truncated.

#### 5.6.1 `root_anchor`

`root_anchor` is a signed member of the `chio.capability.v1` body:

```json
"root_anchor": {
  "kind": "oauth_id_jag",
  "context_digest": "sha256:7d1e...",
  "root_policy_digest": "sha256:aa90...",
  "anchored_at": 1792234795,
  "assertion_exp": 1792235090
}
```

- `root_anchor` is required on every capability `serve-http` admits. A root
  without it rejects.
- `kind` is the closed enum of section 5.6.2. Unknown kinds reject at decode.
- Decoding is strict (section 4.5): an unknown member in `root_anchor`, or
  anywhere in the capability body, rejects at decode, even when the
  signature over the padded body verifies.
- A delegated token copies `root_anchor` byte for byte from its root. Any
  difference denies.
- A root's `expires_at` must not exceed `assertion_exp`. Verifiers check this
  offline.
- `context_digest = SHA-256("chio.delegation-context.v1\0" || canonical_json(context))`.
- `root_policy_digest = SHA-256("chio.root-policy.v1\0" || canonical_json(policy signing body))`.
- Binding to the delegation context, checked at admission and offline:
  `assertion_exp` equals `anchor.token_exp`; `anchored_at` equals
  `exchange.exchanged_at`; the root's issuer key equals
  `exchange.exchange_key`; the root's scope hash equals
  `effective_root_scope_hash`; the root's subject is consistent with
  `exchange.holder` (a `caller` root's subject is the sender key; an
  `edge_session` root has no `cnf.chioSenderKey`).
- For kinds without an external assertion lifetime (`chio_local_as`,
  `chio_operator_key`, `operator_static_bearer`), `assertion_exp` equals the
  local token's, admin request's or minted root's own expiry.

#### 5.6.2 Anchor kinds

The set is closed. Every kind is an exchange kind; there is no self-anchored
root. Every authentication method `serve-http` accepts maps to exactly one
kind. The provider-backed kinds (`oauth_id_jag`, `entra_jwt`,
`entra_agent_id`, `oidc_jwt`, `oauth_introspection`) verify against the
enterprise provider record their rule references (section 5.6.4).

| `kind` | Accepted input | Verified against | Replay key |
|---|---|---|---|
| `oauth_id_jag` | `jwt-bearer` assertion, or RFC 8693 `subject_token_type=urn:ietf:params:oauth:token-type:id-jag`, from an authenticated confidential client | the provider record's issuer and `jwks_url`; `typ` equals the ID-JAG media type; `aud` equals the local authorization server issuer; `client_id` equals the authenticated client; `resource`, when present, equals the advertised protected resource; `exp - iat <= max_assertion_lifetime_secs` | `(issuer, jti)`, single use |
| `entra_jwt` | bearer at the edge, or RFC 8693 `subject_token_type=urn:ietf:params:oauth:token-type:jwt` | the provider record's tenant-specific Entra `jwks_url`; `iss` equals the record's issuer, which must be tenant-specific (`common` and `organizations` issuers reject); `aud` is in the record's `trust_boundary.allowed_audiences` (the provider app ID URI); principal is the claim the record's `subject_mapping.principal_source` names (`oid` for Entra records), and a token without it denies | `(issuer, uti)`, one root per token |
| `entra_agent_id` | bearer at the edge, or RFC 8693 `subject_token_type=urn:ietf:params:oauth:token-type:jwt` | as `entra_jwt`, and the Entra Agent ID agent-identity discriminator claim is present | `(issuer, uti)`, one root per token |
| `oidc_jwt` | bearer at the edge | the provider record's issuer, `trust_boundary.allowed_audiences`, and its `jwks_url` or inline `jwks` | `(issuer, jti)` when `jti` is present, else the token-bytes digest |
| `oauth_introspection` | bearer at the edge | RFC 7662 response from the provider record's `introspection_url` with `active: true`; evidence is the response digest | token-bytes digest |
| `chio_local_as` | access token from the local authorization server `authorization_code` flow, or RFC 8693 re-exchange of such a token (`subject_token_type=urn:ietf:params:oauth:token-type:access_token`) | local authorization server key | local token `jti`; a re-exchange consumes the subject token's `jti` once |
| `chio_operator_key` | operator-issued root through the admin route | pinned operator key | admin request id |
| `operator_static_bearer` | `--auth-token` static bearer at the edge | constant-time comparison against the SHA-256 of the configured token | token-bytes digest plus root expiry, one live root per token |

Matching between the Entra kinds: a token carrying the agent-identity
discriminator claim matches only `entra_agent_id` rules, and a token without
it matches only `entra_jwt` rules. An `oidc_jwt` rule whose provider record
has a Microsoft Entra issuer rejects at load, so every Entra token is held to
the Entra rules.

Entra roots: one root per token, keyed by `(issuer, uti)`. A different token
presenting an already-bound `uti` denies, and a second explicit exchange of
the same token denies. Root lifetime is
`min(now + capability_ttl_secs, token exp, policy.valid_until) - now`.
After the root expires, requests carrying the same token get HTTP 401 with RFC
6750 `error="invalid_token"`. Identity-provider revocation of an Entra
principal takes effect at the expiry of tokens issued before it.

ID-JAG roots: each ID-JAG is single use and yields one root that ends at or
before the ID-JAG's own `exp`. Once the identity provider stops issuing ID-JAGs
for a principal, no root for that principal outlives
`max_assertion_lifetime_secs` plus `max_clock_skew_secs`.

Local re-exchange: a re-exchanged root's scope is the subject root's scope
narrowed by the requested `scope` and `resource`, and its `assertion_exp`
equals the subject root's. Re-exchange is open to the client the subject token
was issued to, including public clients, because it can only narrow.

Bearer intake (`operator_static_bearer`, `oidc_jwt`, `oauth_introspection`,
`entra_jwt`, `entra_agent_id`) maps a token to its root by the SHA-256 of the
exact token bytes. The identity-provider token itself is never stored. The
replay key separately enforces at most one root per assertion: a different
token whose replay key is already bound denies. Replay keys are namespaced by
kind and issuer.

`operator_static_bearer`:

- The rule names `principal` (an operator-chosen identifier such as
  `dev:alice`) and `tenant_value`. The token alone never confers a principal.
- Exactly one `operator_static_bearer` rule may exist. `serve-http` holds only
  the token's SHA-256 after startup. The token is never written to the state
  directory, receipts or logs.
- The delegation context records `issuer = "urn:chio:operator"`, the committed
  principal and tenant, and no `key_snapshot_digest`, `kid`, `alg` or
  `artifact_digest`.
- A verifier reports the identity root for this kind as at most `asserted`:
  the provider's operator states the principal.
- A fresh root is minted when the previous one expires.
- This kind is a development, test and conformance mode.

#### 5.6.3 `chio.delegation-context.v1`

Content-addressed and unsigned. It is bound through `root_anchor.context_digest`
in the signed root.

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
    "exchange_key": "9f2c...",
    "exchanged_at": 1792234795,
    "request_digest": "sha256:0b77...",
    "holder": "edge_session"
  },
  "root_policy_rule_id": "okta-crm-agents",
  "effective_root_scope_hash": "sha256:c3d2..."
}
```

- `artifact_digest` is the SHA-256 of the exact compact JWS bytes received.
- `provider_record_id` and `provider_identity_digest` name the provider
  record the exchange verified against and the digest of its identity
  projection (section 5.6.4), which equals the matched rule's. `issuer`
  equals the record's issuer. Both members are present for provider-backed
  kinds and absent for `chio_local_as`, `chio_operator_key` and
  `operator_static_bearer`.
- Decoding is strict (section 4.5): an unknown member in the context,
  `anchor`, `exchange`, a commitment object or `claims` rejects. `claims`
  keys are exactly the rule's `recorded_claims` names.
- `artifact_retained` is `true` only for `oauth_id_jag` under a rule with
  `retain_idp_artifact: true`. The retained token is stored in the evidence
  store keyed by `artifact_digest`, never in the context, receipts or logs.
  For every other kind it is `false`.
- `subject` and `tenant` are salted commitments:
  `commit = SHA-256(domain || salt || utf8(value))`, where `domain` is
  `chio.delegation-context.subject.v1\0` or
  `chio.delegation-context.tenant.v1\0` and `salt` is 32 bytes from the host
  RNG, fresh per context. Salts live in the disclosure store under `salt_ref`.
- `claims` holds only the claims the matched rule names in `recorded_claims`,
  each plain or committed per the rule. A committed claim is
  `SHA-256("chio.delegation-context.claim.v1\0" || utf8(name) || 0x00 || salt || canonical_json(value))`
  with its own 32-byte salt.
- `holder` is `edge_session` or `caller` (section 5.6.6).
- `key_snapshot_digest`, `kid`, `alg` and `artifact_digest` are present for
  the JWS-verified kinds (`oauth_id_jag`, `entra_jwt`, `entra_agent_id` and
  `oidc_jwt`).

#### 5.6.4 `chio.root-policy.v1`, provider records and `chio.idp-key-snapshot.v1`

The root policy is signed by the provider's policy key.

```json
{
  "schema": "chio.root-policy.v1",
  "policy_id": "rp_acme_prod",
  "policy_key": "41aa...",
  "exchange_keys": ["9f2c..."],
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

- `policy_key` must equal the key pinned in `serve-http` configuration
  (`--root-policy-key`). A mismatch refuses startup.
- `valid_from` and `valid_until` are checked at startup and on every exchange
  and admission against the authority clock. Outside the window, startup
  refuses and running exchanges and admissions deny.
- Exactly one policy is loaded. A root whose `root_policy_digest` names
  another policy denies. Every policy a bundle's roots reference is exported
  with the bundle.

Rule constraints:

- Provider-backed kinds require `provider_record_id` and
  `provider_identity_digest` in `match`. The rule holds no issuer, key
  location, endpoint, audience, tenant claim or principal claim; those come
  only from the provider record. A token matches a rule only when its `iss`
  equals the issuer of the rule's provider record and the rule's other
  `match` members hold. Keys are fetched only from the record's `jwks_url` or
  taken from its inline `jwks`.
- The effective root scope is the intersection of `ceiling_scope` and the
  projection of the identity provider's scope values. A scope value absent
  from `idp_scope_projection` denies the exchange. An identity provider that
  sends no scope gets the empty projection, which denies.
- Exactly one rule must match. Zero or more than one denies.
- `capability_ttl_secs` defaults to 300. `max_assertion_lifetime_secs`
  defaults to 300 and applies to `oauth_id_jag`; it must be absent on
  `entra_jwt` and `entra_agent_id` rules.
- `max_clock_skew_secs` is at most 60.
- `retain_idp_artifact` is allowed only on `oauth_id_jag` rules.
- `allowed_algs` is required on the JWS-verified kinds and absent on
  `oauth_introspection` rules, which verify no JWS.
- `principal` and `tenant_value` are required on `operator_static_bearer`
  rules and rejected on every other kind. `provider_record_id`,
  `provider_identity_digest`, `allowed_algs` and `idp_scope_projection` are
  absent on that kind, and its effective root scope is `ceiling_scope`.
  `chio_local_as` and `chio_operator_key` rules carry no provider members
  either.
- An `oidc_jwt` rule whose provider record has a Microsoft Entra issuer
  rejects.
- Decoding is strict (section 4.5): an unknown member in the policy, a rule,
  `match`, `disclosure` or a `tools` entry rejects at load, even under a
  valid policy signature.
- `disclosure` is defined in "Committed Receipts And Disclosure" in section 6.

Load rules: the policy loads at startup. A policy that fails signature,
pinned-key match, validity window, schema, ceiling-hash recomputation, pointer
syntax or bound checks refuses startup. A provider-backed rule whose record is
missing from the registry, of the wrong record kind, invalid, lacking a member
its kind needs, or whose identity digest differs from
`provider_identity_digest` also refuses startup. A disabled record does not
refuse startup; it denies at runtime.

Provider records. The enterprise provider registry
(`chio.enterprise-providers.v1`, `--enterprise-providers-file`, section 10.3)
is the one source of provider identity. A record referenced by a rule is
valid and carries:

- record kind `oidc_jwks` for `oauth_id_jag`, `entra_jwt`, `entra_agent_id`
  and `oidc_jwt` rules, with `issuer` and exactly one of `jwks_url` (`https`)
  or an inline `jwks`. The exchange never follows `discovery_url`.
  `entra_jwt`, `entra_agent_id` and `oidc_jwt` records also carry a
  non-empty `trust_boundary.allowed_audiences`;
- record kind `oauth_introspection` for `oauth_introspection` rules, with
  `issuer` and an `https` `introspection_url`. The credentials the edge
  presents to that endpoint are `serve-http` secrets and never appear in the
  registry;
- `subject_mapping.principal_source`, the one claim that is the principal,
  and `subject_mapping.tenant_id_field`, the tenant claim (`iss` for
  per-organization Okta issuers, `tid` for Entra), which feeds the tenant tag
  (section 5.6.8);
- `provenance.trust_material_ref`.

`scim` and `saml` records are never referenced by a rule. Records carry no
`provider_profile` member.

The provider identity projection is unsigned and content-addressed:

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

- It holds the record's id, kind, issuer, key source (`jwks_url`, `jwks` or
  `introspection_url`), audiences, subject mapping and trust material
  reference. It excludes `enabled`, other provenance labels and validation
  errors.
- `provider_identity_digest = SHA-256("chio.enterprise-provider-identity.v1\0" || canonical_json(projection))`.
- It decodes strictly and is exported in bundles, so a verifier can recompute
  the digest a rule pins.

Every exchange, and every admission under a root whose anchor names a
provider record, loads the registry once and checks the record against that
one version. A missing, disabled or invalid record, a record of the wrong
kind, or a recomputed identity digest that differs from the rule's denies. An
unreadable or invalid registry answers HTTP 503 on the token endpoint and
bearer intake and denies admission. No cached registry or fallback copy is
used. A change to a record's identity projection takes effect only with a
root policy re-signed by the policy key.

The identity-provider key snapshot is signed by the exchange key:

```json
{
  "schema": "chio.idp-key-snapshot.v1",
  "issuer": "https://acme.okta.com",
  "source": "https://acme.okta.com/oauth2/v1/keys",
  "keys": [ { "kid": "k-okta-1", "kty": "RSA", "alg": "RS256", "n": "...", "e": "AQAB" } ],
  "observed_at": 1792230000,
  "exchange_key": "9f2c...",
  "signature": "..."
}
```

The exchange writes a snapshot each time its fetched key set changes. For a
record with an inline `jwks`, `source` is `registry:<provider_id>`. A
snapshot is in force from `observed_at` until the next snapshot's
`observed_at` for the same issuer. Each delegation context names the snapshot
and `kid` it used. A snapshot is the provider's statement of what the identity
provider published, not identity-provider evidence.

A JWKS document is accepted only when it parses within a size cap. A key is
kept only when `use` is absent or `sig`, its `alg` (when present) matches the
token `alg`, and an RSA modulus is at least 2048 bits.

#### 5.6.5 `chio.capability-presentation.v1`

Carried in MCP `_meta.chioCapability` (WIRE_PROTOCOL section 3.6).

```json
{
  "schema": "chio.capability-presentation.v1",
  "leaf": { "schema": "chio.capability.v1", "...": "..." },
  "ancestors": [ { "schema": "chio.capability.v1", "...": "root" }, { "...": "parent" } ],
  "delegation_context": { "schema": "chio.delegation-context.v1", "...": "..." }
}
```

- `ancestors` is ordered root to parent, matching the W1.1 chain-binding rule.
  A root presented alone has `ancestors: []`.
- `delegation_context` is required when the presenter is not the session
  holder, so the verifier can recompute `context_digest`.
- The envelope is unsigned. Every member inside is verified independently.
- Decoding is strict (section 4.5): an unknown member in the envelope or in
  any member it carries rejects the presentation.

#### 5.6.6 Holder classes

| Caller | Capability subject | Holder | Proof-required grants |
|---|---|---|---|
| MCP client without a Chio sender key | fresh per-exchange Ed25519 public key; the private half is discarded at mint | `edge_session`, bound to the token that produced the root | unavailable; the exchange denies if the matched rule's ceiling includes them for this holder class |
| Chio-aware client with `cnf.chioSenderKey` | the sender key | `caller` | available |

An `edge_session` root can never sign a delegation or a DPoP proof, because
its subject private key does not exist after mint.

#### 5.6.7 Revocation

The `/admin/revocations` route writes to the SQLite revocation store under the
state directory. Target kinds are closed:

| Target | Effect |
|---|---|
| `capability_id` | that capability and every descendant |
| `root_policy_rule` | every root minted under the rule |
| `anchor_subject` | every root whose principal has the given subject tag; the admin supplies issuer and plaintext subject, and only the tag is stored |
| `tenant_tag` | every root in the tenant; the admin supplies issuer and tenant value, and only the tag is stored |
| `replay_key` | the root minted from one assertion, by `(kind, issuer, jti or uti)` |

Each anchored root row stores its rule id, subject tag and tenant tag, so
every target is an indexed equality lookup at exchange and at admission.

A revocation is one serving-writer transaction on the state-directory
database, acknowledged after it commits and the authority anchor syncs. Let T
be that commit. Every budget authorize-hold transaction (where an admission
commits) that begins after T denies, and the call does not dispatch. Every
root-exchange mint transaction that begins after T and matches the entry
refuses. A call admitted before T may dispatch; its budget capture and native
dispatch capture re-check revocation in the capture transaction, and a capture
that begins after T refuses after the upstream effect has run, withholding the
remaining output and ending the call with a revocation denial. The
allowed-receipt check is one read per id in the call's chain (the leaf, then
each ancestor), each separate from the others and from the receipt append. If
the read of the id the revocation marked begins after T the allowed receipt is
refused; if it began before T the allowed receipt is appended, even when later
reads or the append land after T. An acknowledgement
does not guarantee that no allowed receipt is appended after it, nor that a
call admitted before it completes. A denied call's receipt
names the matching revocation entry id in its guard evidence. Revocation
entries are exported in bundles with tags, never with plaintext subjects or
tenants. No identity-provider push channel is consumed.

Caller revocation request, signed by `revoker_key`:

```json
{
  "schema": "chio.revocation-request.v1",
  "target_capability_id": "cap_01J...child",
  "revoker_key": "41aa...",
  "presentation_digest": "sha256:...",
  "reason": "subagent_retired",
  "issued_at": 1792235000,
  "signature": "..."
}
```

- Submitted to `POST /v1/revocations` on `serve-http`. The provider accepts it
  only if `revoker_key` is the subject of a strict ancestor of the target in
  the retained presentation named by `presentation_digest`, and that ancestor
  is not revoked. A caller can revoke only its own delegated descendants.
- `issued_at` must be within the rule's clock skew of the provider's clock.
  Duplicate requests are idempotent.
- The accepted request is stored and exported. The provider answers with the
  revocation entry id.
- An invalid signature, a `revoker_key` that is not a strict-ancestor subject
  in the named presentation, a revoked ancestor, a target that is not a
  descendant, or an `issued_at` outside skew rejects with no state change.

#### 5.6.8 Tenant and subject tags, and verifier trust

- Tags are keyed index values of the provider's tenant index key set
  (`--tenant-index-keys <dir>`, 32-byte keys), under the HKDF purpose subkeys
  of section 6: `tenant_tag = HMAC-SHA256(K[tenant-tag], "chio.tenant-tag.v1" || 0x00 || issuer || 0x00 || tenant_value)`,
  where `issuer` is the provider record's issuer and `tenant_value` is the
  claim named by the record's `subject_mapping.tenant_id_field`, and
  `subject_tag = HMAC-SHA256(K[subject-tag], "chio.subject-tag.v1" || 0x00 || issuer || 0x00 || subject)`.
- Every tag carries the `key_id` of the generation it was derived under. A
  tenant tag carried as a string uses `tt1.<hex key_id>.<hex value>` and a
  subject tag uses `st1.<hex key_id>.<hex value>`. Each is parsed exactly under
  its own purpose: a revocation entry whose `target_kind` is `tenant_tag`
  refuses an `st1` target, and one whose `target_kind` is `anchor_subject`
  refuses a `tt1` target.
- New tags use the active generation. A lookup or revocation match computes
  the candidate from plaintext it holds under every loaded generation and
  matches on `(key_id, value)`. A retired generation stays loaded while any
  stored tag or revocation entry references it; startup refuses when one is
  missing, and an unknown `key_id` refuses.
- The keys never leave the process and are not signing keys.
- Tags are stored in SQLite columns beside each root and receipt. They are not
  part of any signed artifact. No plaintext tenant id or subject is stored
  outside the salted commitments in the delegation context.

`chio.verifier-trust.v1` is a local, unsigned file the verifying party writes
and controls:

```json
{
  "schema": "chio.verifier-trust.v1",
  "kernel_keys": ["9f2d..."],
  "exchange_keys": ["9f2c..."],
  "root_policy_keys": ["41aa..."],
  "idp_keys": { "https://acme.okta.com": [ { "kid": "k-okta-1", "kty": "RSA", "n": "...", "e": "AQAB" } ] },
  "pep_keys": { "kong-prod-eu": "77b0..." },
  "checkpoint_keys": [],
  "required_columns": ["identity_root", "delegation_chain", "decision", "content"]
}
```

`idp_keys` is optional. A verifier that pins the identity provider's keys can
report the identity root as `verified`; without them it reports at most
`observed` for a retained artifact.

#### 5.6.9 Keys and signers

Three provider keys and one local authorization server key are distinct and
pinned separately:

- exchange key: signs root capabilities and identity-provider key snapshots.
  Pinned in verifier trust files.
- kernel key: signs receipts, settlement closures and export commitments.
  Pinned in verifier trust files.
- policy key: signs the root policy. Pinned in `serve-http` configuration and
  in verifier trust files.
- local authorization server key: signs local JWS access tokens. Never pinned
  by verifiers.

The exchange signer is a local seed file (`--exchange-signer seed-file:<path>`)
or a remote trust-control signer (`--exchange-signer trust-control:<url>` with
`--exchange-signer-credential-file` and `--exchange-signer-trusted-public-keys`,
the rotating set of keys trust-control may sign roots with). It never reads
`--control-url` or `--control-token`, and `serve-http` refuses both. A missing,
unreadable or wrongly permissioned seed file or credential file refuses
startup. An unreachable trust-control, a response of another kind or for
another body, or a returned signature that does not verify under a key in the
trusted set fails the mint. No signer falls back to a generated or local key.

#### 5.6.10 Fail-closed rules

Every rule below denies, rejects at load, or refuses startup. None degrades to
a weaker mode.

Exchange:

- Unsupported `grant_type`, `subject_token_type` or `requested_token_type`.
- Client authentication: a `jwt-bearer` or `token-exchange` request with an
  external subject token from a public client, without a client assertion,
  with an assertion whose signature fails against the registered client key,
  whose `aud` is not the token endpoint URL, whose lifetime exceeds 60 s, or
  whose `jti` was already used.
- JWT header: `alg` not in the rule's `allowed_algs` (`none` and HMAC
  algorithms are never allowed); `typ` mismatch for `oauth_id_jag`; `kid`
  absent; any of `jku`, `x5u`, `jwk`, `x5c` or `crit` present.
- `kid` not in the current key set after at most one rate-limited refresh.
- Provider registry unreadable or invalid (HTTP 503, no exchange); the rule's
  provider record missing, disabled, invalid or of the wrong kind; the
  record's recomputed identity digest different from the rule's
  `provider_identity_digest`.
- Signature invalid. `iss` not exactly the provider record's issuer. `aud`
  not exactly the local authorization server issuer (ID-JAG), or not in the
  record's `trust_boundary.allowed_audiences` (Entra, OIDC JWT).
  ID-JAG `resource` present and not equal to the advertised protected
  resource.
- Time: `exp` or `iat` missing; `now >= exp + skew`; `iat > now + skew`;
  `nbf > now + skew`; for ID-JAG, `exp - iat > max_assertion_lifetime_secs`;
  computed root `expires_at <= now`. Every time read goes through the
  authority clock.
- Replay key missing where required, or already bound. The replay store is
  durable and retained until `exp + skew`.
- ID-JAG `client_id` not equal to the authenticated client.
- Token without the claim the provider record's
  `subject_mapping.principal_source` names, or without the claim its
  `tenant_id_field` names. A token carrying the agent-identity discriminator
  claim matched against an `entra_jwt` rule, or one without it matched
  against an `entra_agent_id` rule. Any Entra issuer on an `oidc_jwt` rule's
  provider record.
- Static bearer token not equal to the configured token.
- Local re-exchange whose subject token is expired, revoked or already
  re-exchanged, or whose requested scope or `resource` is not a subset of the
  subject root's.
- Any string feeding a tag or commitment that contains a NUL character.
- Root policy outside `valid_from`/`valid_until`; zero or more than one
  matching rule; a scope value missing from the projection; empty effective
  scope; requested holder class not in `holder_classes`; proof-required grants
  for an `edge_session` root.
- JWKS endpoint unreachable, oversized or invalid: no exchange. Existing roots
  live until their expiry.
- Exchange signer failure: no mint.
- Any revocation entry matching the would-be root (rule, subject tag, tenant
  tag, replay key): no mint.

Edge admission:

- Root without `root_anchor`, signed by a key outside the root policy's
  `exchange_keys`, or naming a `root_policy_digest` that is not the loaded
  policy. Loaded policy outside its validity window.
- An unknown member at any level of a presented capability, presentation or
  delegation context, including an added or altered `algorithm` member. The
  rejection happens at decode, before any verifier is chosen (section 4.5).
- For a root whose anchor names a provider record: the registry, loaded once
  for this request, is unreadable or invalid, or the record is missing,
  disabled, invalid, or its identity digest differs from the one the
  delegation context names.
- Root `expires_at > root_anchor.assertion_exp`.
- `context_digest` mismatch against the presented or stored delegation
  context, or any binding in section 5.6.1 failing.
- Delegated token whose `root_anchor` differs from its root's. Ancestor
  evidence missing, reordered, unsigned or not covering every hop (W1.1).
- Any token in the chain matched by a revocation entry. The revocation read
  happens in the admission transaction; a store error denies.
- OAuth access tokens and identity-provider bearer tokens are accepted only as
  handles to an exchange-issued root (the `chio_root` claim, or the
  token-digest mapping for bearer intake). A token with no stored root denies.

Startup refusals. `serve-http` refuses to start when:

- no root policy is configured, or it fails any load rule in section 5.6.4;
- a provider-backed rule exists and `--enterprise-providers-file` is not set,
  or the registry is unreadable or invalid;
- the root policy's `policy_key` differs from `--root-policy-key`;
- the state-directory lock is held by another process, or the state directory
  is on a network filesystem;
- the kernel signer is ephemeral or missing;
- any two of the exchange, kernel, policy and local authorization server keys
  are equal;
- a seed file is readable by group or other, or not owned by the process user;
- the tenant index key set has no active key, a key that is not 32 bytes or a
  duplicate `key_id`, or lacks a generation a stored tag or revocation entry
  references;
- durable admission is off;
- `--auth-token` is set without exactly one `operator_static_bearer` rule
  naming a `principal`, or such a rule exists without `--auth-token`;
- `--control-url` or `--control-token` is set;
- `--exchange-signer trust-control:<url>` is set without
  `--exchange-signer-credential-file` and `--exchange-signer-trusted-public-keys`;
- the signer credential's secret equals `--auth-token`, the admin token, or any
  other credential the edge accepts or presents.

#### 5.6.11 Deployment limits

- One `serve-http` process serves one provider state directory.
  `--state-dir` is the only way to place stores; every SQLite file the process
  writes lives under it.
- Before opening any store, the process takes an OS advisory exclusive lock on
  `<state-dir>/LOCK` and holds it for its lifetime. If the lock is held,
  startup refuses. The OS releases the lock when the process exits, so a crash
  leaves no stale lock.
- The state directory must be on a local filesystem. Startup refuses a network
  filesystem, where advisory locks are unreliable.
- A rolling deployment that starts the new process before the old one exits
  fails by design. Deploy with stop-then-start.
- Restoring a state-directory backup rewinds the replay store. An assertion
  used after the backup and still inside its lifetime could be exchanged
  again. After a restore, wait `max_assertion_lifetime_secs + max_clock_skew_secs`
  before serving.
