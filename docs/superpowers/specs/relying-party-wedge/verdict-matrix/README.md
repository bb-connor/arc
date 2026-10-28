# Staged verdict-matrix scenarios: anchored_root, receipt_disclosure, revocation_local

Planning material for the relying-party wedge (spec section 11.3, section 12 M0 exit "scenario files written (expected to fail)"). These 50 files (24 `anchored_root`, 12 `receipt_disclosure`, 14 `revocation_local`) are staged, not executed. The live corpus under `crates/tooling/chio-conformance/verdict_matrix/scenarios/` cannot hold them yet: `ScenarioCategory` (`crates/tooling/chio-conformance/verdict_matrix/src/lib.rs:49`) is a closed enum, `manifest.toml` pins the scenario count, per-category counts and the index hash, and no driver implements `rust-mcp-serve-http`. "Expected to fail" therefore means: staged here, and failing until the M1 code that implements each behavior lands.

## File shape

Each file holds one `chio.verdict-matrix.scenario.v1` object on a single line, in the field order of the live corpus:

```json
{"schema":"chio.verdict-matrix.scenario.v1","id":"<category-kebab>-NNN-<suffix>","title":"...","category":"<directory name>","description":"...","tags":["<category>","<verdict>"],"requires":["rust-kernel","rust-mcp-serve-http"],"script":{"operation":"...","setup":["..."],"mutation":"..." | null},"expected":{"verdict":"allow" | "deny","reason_code":"urn:chio:error:...","scope_set":["..."]}}
```

- `id` equals the file name without `.json`.
- `category` equals the directory name: `anchored_root`, `receipt_disclosure` or `revocation_local`.
- `requires` names the existing required driver `rust-kernel` and the new `rust-mcp-serve-http` driver (spec 11.3), which runs a real `serve-http` process against the local IdP stub. `receipt-disclosure-008` names `rust-kernel` only, because its fault injection runs in process.
- `expected.scope_set` is `["tool:read"]` for `tool.call` scenarios and `[]` for `exchange`, `export` and `policy.load` scenarios, which admit no tool call.
- All fixture timestamps are fixed: `issued_at = 1792234800`. Assertion fixtures use `iat = 1792234790` and `exp = 1792235090`, and the root policy window is `valid_from = 1792000000`, `valid_until = 1799999999` (spec 7.3 and 7.4 examples).

## Operations

| `operation` | What the driver does | Where the verdict is read |
|---|---|---|
| `tool.call` | Starts `serve-http` with the setup fixtures, obtains a root through the intake the fixtures name (bearer at the edge, local AS login, exchange or admin route), applies the mutation, then sends one `tools/call` for `files.read` with required scope `tool:read`. | The admission decision and its signed receipt. |
| `exchange` | Sends one token request to the local AS token endpoint (`jwt-bearer` or RFC 8693 `token-exchange`, or bearer intake at the edge for Entra), after applying the mutation. | Whether a root is minted. `allow` means minted, `deny` means refused with the reason code. |
| `export` | Records receipts through `tool.call` first (fixture `recorded_receipts`), then runs one evidence export with the profile the mutation names. | Whether the export is written, and the contents checks in the scenario description. |
| `policy.load` | Starts `serve-http` with the root policy fixture named in `setup`. | Whether startup succeeds. `deny` means startup refuses with the reason code. |

## Setup fixtures

| Name | Definition |
|---|---|
| `serve_http_edge` | One `serve-http` process with a fresh state directory, durable admission on, and the local AS enabled. |
| `root_policy` | A signed `chio.root-policy.v1` with one rule per M1 anchor kind (`oauth_id_jag`, `oidc_jwt`, `oauth_introspection`, `chio_local_as`, `chio_operator_key`, `operator_static_bearer`, `entra_jwt`), `disclosure.default = "committed"`, no `tools` map, `ceiling_scope` granting `tool:read`, `capability_ttl_secs = 300`, `max_clock_skew_secs = 30`. Its `policy_key` equals the configured `--root-policy-key`. Each provider-backed rule names a `provider_registry` record by `provider_record_id` and pins its `provider_identity_digest`; no rule carries an issuer, key location, endpoint or tenant claim (spec section 2.5, G17). |
| `provider_registry` | A `chio.enterprise-providers.v1` file given to `serve-http` as `--enterprise-providers-file`, with one enabled, valid record per provider-backed rule: `oidc_jwks` records for the ID-JAG, OIDC JWT and Entra issuers on `idp_stub_jwks` (each with `jwks_url`, `subject_mapping.principal_source`, `subject_mapping.tenant_id_field` and `provenance.trust_material_ref`; the Entra record has `principal_source = "oid"`, `tenant_id_field = "tid"` and the provider app ID URI in `trust_boundary.allowed_audiences`), and an `oauth_introspection` record whose `introspection_url` is `introspection_stub`. Every scenario whose intake uses one of these providers names it. |
| `root_policy_entra_issuer_on_oidc_jwt` | `root_policy` plus one `oidc_jwt` rule whose provider record has a tenant-specific Microsoft Entra issuer. |
| `root_policy_padded_rule` | `root_policy` with one extra member (`"pad": 0`) in one rule's `match` object, signed by the configured policy key. |
| `root_policy_inline_tools` | `root_policy` plus `disclosure.tools` naming `files/read` with empty `inline_fields` lists. |
| `root_policy_inline_pointer` | `root_policy` plus `disclosure.tools.files/read.parameters.inline_fields = ["/path"]`. |
| `tenant_index_key` | A tenant index key set directory with one 32-byte active key (`0x14 * 32`), fixture material only. |
| `kernel_seed` | A kernel signing seed file with mode 0600, distinct from the exchange, policy and local AS keys. |
| `exchange_key` | The exchange signing key listed in the root policy's `exchange_keys`, available to the mutation that mints a forged root. |
| `idp_stub_jwks` | Local IdP stub serving a JWKS over `https` with one RS256 key, `kid = "k-stub-1"`, `use = "sig"`, 2048-bit modulus. It also mints Entra-shaped tokens with a tenant-specific issuer. |
| `id_jag_minter` | Mints ID-JAG assertions from `idp_stub_jwks`: `typ` from the pinned draft, `aud` equal to the local AS issuer, `client_id = "mcp-client-fixture"`, a fresh `jti` per assertion, `iat` and `exp` as above, `scope = ["tool.read"]` projected to `tool:read` by the rule. |
| `confidential_client_key` | The registered client key for `mcp-client-fixture` (`token_endpoint_auth_method = private_key_jwt`); requests carry a client assertion with `aud` equal to the token endpoint URL and a 60 s lifetime. |
| `public_client` | A client registration for `mcp-client-fixture` with `token_endpoint_auth_method = none`. |
| `oidc_jwt_minter` | Mints bearer JWTs for the `oidc_jwt` rule from a non-Entra issuer on `idp_stub_jwks`, with `sub`, a tenant claim and a `jti`. |
| `introspection_stub` | RFC 7662 endpoint that reports `active: true` for `opaque_bearer_token` and `active: false` for anything else. |
| `opaque_bearer_token` | One opaque bearer token string known to `introspection_stub`. |
| `local_as_login` | Completes the local AS `authorization_code` flow and yields a local AS access token. |
| `operator_admin_key` | The pinned operator key used to call the admin route that issues a `chio_operator_key` root. |
| `static_bearer_token` | The `--auth-token` value given to `serve-http`. Only its SHA-256 is held after startup. |
| `static_bearer_principal` | The single `operator_static_bearer` rule with `principal = "dev:alice"` and `tenant_value = "dev-tenant"`. |
| `entra_token_with_uti` | An Entra application token from `idp_stub_jwks` with a tenant-specific `iss`, `tid`, `oid`, `aud` equal to the provider app ID URI, and a `uti` claim, matched by the `entra_jwt` rule through its `provider_registry` record (`tenant_id_field = "tid"`). |
| `second_stub_jwks` | A second local JWKS over `https` with its own RS256 key, which signs the token presented after `change_provider_jwks_url`. |
| `guard_with_undeclared_evidence_field` | A guard that allows the call and emits one evidence field it has not declared safe under committed disclosure. |
| `argument_marker` | Call arguments carrying the marker string `chio-fixture-marker-7f3a`. |
| `streaming_tool` | A tool whose result is a stream of three chunks. |
| `delegated_child` | A token delegated from the live root under the same `root_anchor` (depth 1 is used only to exercise the existing revocation cascade, not portable chains). |
| `two_tenants` | Two `oidc_jwt` principals from tenants A and B, each with recorded receipts. |
| `recorded_receipts` | Receipts produced by earlier `tool.call` steps in the same scenario, stored with their openings in the disclosure store. |

## Mutations

| Name | Effect |
|---|---|
| `null` | None. |
| `repeat_same_bearer_token` | Presents the same Entra token twice; both calls resolve to the one root keyed by `(issuer, uti)`. |
| `omit_client_assertion` | Sends the `jwt-bearer` request from `public_client` with no client assertion. |
| `replay_id_jag_jti` | Exchanges one ID-JAG successfully, then presents a second ID-JAG with the same `(issuer, jti)`. |
| `second_token_same_uti` | After one Entra token is exchanged, presents a different Entra token whose `uti` equals the first token's. |
| `multi_tenant_issuer` | Presents an Entra token from `idp_stub_jwks` whose `iss` is the multi-tenant `organizations` issuer. |
| `reuse_token_after_root_expiry` | Calls once with the Entra token, advances the injected clock past the root's `expires_at` (the token's `exp` is still in the future), then calls again with the same token. |
| `root_signed_by_unlisted_key` | Mints a root with a well-formed `root_anchor`, signed by a key that is not in the root policy's `exchange_keys`, and presents it at the edge. |
| `strip_root_anchor` | Mints a root with `exchange_key` that carries no `root_anchor` and presents it at the edge. |
| `disable_provider_after_root` | Obtains a root through the `oidc_jwt` intake, sets the provider record's `enabled` to `false` through the registry writer, waits for the durable write, then calls under the live root. A second step exchanges a fresh token from the same issuer and expects the same denial. |
| `remove_provider_record` | Removes the `oidc_jwt` rule's provider record through the registry writer, then exchanges a token from that issuer. |
| `corrupt_provider_registry` | Replaces the registry file with bytes that do not decode as `chio.enterprise-providers.v1`, then exchanges. The token endpoint or bearer intake answers HTTP 503. |
| `corrupt_provider_registry_after_root` | Obtains a root through the `oidc_jwt` intake, corrupts the registry file as above, then calls under the live root. |
| `change_provider_jwks_url` | Points the `oidc_jwt` record's `jwks_url` at `second_stub_jwks` without re-signing the root policy, then exchanges a token signed by the second key set. |
| `pad_root_anchor` | Mints a root with `exchange_key` whose `root_anchor` carries one extra member (`"pad": 0`), signs the padded body, and presents it at the edge. |
| `add_capability_algorithm_member` | Mints an Ed25519 root with `exchange_key`, adds a top-level `"algorithm": "p256"` member after signing, and presents it at the edge. |
| `root_expires_after_assertion_exp` | Mints a root with `exchange_key` whose `expires_at` is one second past `root_anchor.assertion_exp`. |
| `request_scope_outside_root` | Calls a tool needing `tool:write` under a root that grants only `tool:read`. |
| `body_tenant_id_with_authority` | Test hook that sets `tenant_id` on a receipt body that also carries `authority`, before signing. |
| `export_auditor_hash_only` | Runs an `auditor_hash_only` export. |
| `export_auditor_with_salt_only_opening` | In-process fault injection that adds a salt-only opening (`payload: null`) to an auditor-profile export assembly; the export request has no member that asks for an opening. |
| `export_caller_without_tenant_tags` | Runs a `caller` export with no `tenant_tags`. |
| `export_caller_tenant_a` | Runs a `caller` export with tenant A's tag. |
| `revoke_capability_id` | Revokes the live root by `capability_id` through `/admin/revocations`, then calls. |
| `revoke_parent_capability` | Revokes the root by `capability_id`, then calls under `delegated_child`. |
| `revoke_root_policy_rule` | Revokes the matching rule by `root_policy_rule`, then calls. |
| `revoke_anchor_subject` | Revokes the principal by issuer and plaintext subject (`anchor_subject`), then calls. |
| `revoke_tenant_tag` | Revokes by issuer and tenant value (`tenant_tag`), then calls. |
| `revoke_replay_key` | Revokes by `(kind, issuer, jti)` (`replay_key`), then calls. |
| `revoke_before_exchange` | Writes a revocation entry that matches the would-be root (rule, subject tag, tenant tag or replay key), then exchanges. |
| `revocation_store_read_error` | Fault injection that makes the revocation read inside the admission transaction fail. |
| `revoke_and_acknowledge_then_call` | Waits for the admin route's acknowledgement of a revocation, then calls. |
| `revoke_before_capture` | Starts a streaming call, lets its admission commit, then revokes and waits for acknowledgement before the budget capture begins. |
| `revoke_after_capture_before_receipt_check` | Lets the call's capture commit, then revokes and waits for acknowledgement before the allowed-receipt check begins. |
| `revoke_after_receipt_check_before_append` | Lets the allowed-receipt check pass, then revokes and waits for acknowledgement before the receipt append runs. `revocation-local-010c` expects `allow` because this is the disclosed check-to-append gap; the PR that closes the gap flips it to `deny` with `urn:chio:error:capability:revoked` and re-pins the manifest. |
| `revoke_anchor_subject_inspect_store` | As `revoke_anchor_subject`, then reads the stored revocation row and checks it holds the subject tag and no plaintext subject or tenant. |
| `revoke_other_subject` | Revokes a different principal by `anchor_subject`, then calls under the fixture principal. |

## Reason codes

Codes taken from the live corpus:

| Code | Used for | Source |
|---|---|---|
| `urn:chio:error:none` | every allow | `verdict_matrix/scenarios/capability_subset/` |
| `urn:chio:error:capability:scope-exceeded` | `receipt-disclosure-002` | `verdict_matrix/scenarios/capability_subset/` |
| `urn:chio:error:capability:revoked` | revocation denies | `verdict_matrix/scenarios/revocation_propagation/` |

Codes for the new behavior, in existing error domains (spec section 2.5, G12). Each is registered in `spec/errors/registry.yaml` by the M1 PR that first emits it:

| Code | Scenarios |
|---|---|
| `urn:chio:error:transport:exchange-client-unauthenticated` | anchored-root-008 |
| `urn:chio:error:transport:exchange-replay` | anchored-root-009, anchored-root-012, anchored-root-014 |
| `urn:chio:error:transport:exchange-issuer-not-allowed` | anchored-root-013 |
| `urn:chio:error:transport:exchange-revoked` | revocation-local-007 |
| `urn:chio:error:capability:root-anchor-missing` | anchored-root-010 |
| `urn:chio:error:capability:root-anchor-lifetime` | anchored-root-011 |
| `urn:chio:error:capability:root-exchange-key-untrusted` | anchored-root-016 |
| `urn:chio:error:transport:exchange-provider-unavailable` | anchored-root-018 |
| `urn:chio:error:transport:exchange-provider-registry-unreadable` | anchored-root-019 |
| `urn:chio:error:transport:exchange-provider-identity-mismatch` | anchored-root-020 |
| `urn:chio:error:capability:root-provider-unavailable` | anchored-root-017, anchored-root-021 |
| `urn:chio:error:capability:strict-decode-rejected` | anchored-root-022, anchored-root-023 |
| `urn:chio:error:policy:root-policy-strict-decode-rejected` | anchored-root-024 |
| `urn:chio:error:policy:root-policy-entra-issuer-on-oidc-rule` | anchored-root-015 |
| `urn:chio:error:policy:root-policy-inline-disclosure-unavailable` | receipt-disclosure-011, receipt-disclosure-012 |
| `urn:chio:error:attest:receipt-tenant-id-with-authority` | receipt-disclosure-005 |
| `urn:chio:error:attest:export-salt-only-opening` | receipt-disclosure-008 |
| `urn:chio:error:attest:export-tenant-tag-required` | receipt-disclosure-009 |
| `urn:chio:error:kernel:revocation-store` | revocation-local-008 |

No error domain is added. Exchange failures are token endpoint authentication failures (`transport`), anchor and root failures are capability validation (`capability`), root-policy load failures are `policy`, and receipt signing and export failures are `attest`. Revocation-store failures report the non-URN code `CHIO-KERNEL-REVOCATION-STORE` today (`crates/kernel/chio-kernel/src/kernel/error.rs:788`); M1 item 5 converts it to `urn:chio:error:kernel:revocation-store`.

## Inline disclosure flip

`receipt-disclosure-011` and `receipt-disclosure-012` expect `deny` at policy load because M1 rejects a non-empty `disclosure.tools` map (spec 7.4, 13.1). When inline disclosure lands (M2), both flip to `allow` and their reason code becomes `urn:chio:error:none`. The PR that lands inline disclosure updates both files and re-pins the manifest.

## Counts against spec 11.3

Spec 11.3 lists `anchored_root` at 24 scenarios for M1, `receipt_disclosure` at 12 and `revocation_local` at 14. All 50 are staged here (spec section 2.5, "Count"). Scenarios 017 to 021 cover the provider registry (G17), 022 and 024 strict decoding (G18), and 023 the deleted `algorithm` member (G19). Padding negatives for the receipt blocks, the opening document and the other section 7 types are conformance vectors (spec 11.2), not scenarios. M2 adds four `anchored_root` scenarios for Entra Agent ID.

## Move-in checklist for M1

1. `git mv` each category directory into `crates/tooling/chio-conformance/verdict_matrix/scenarios/` in the PR that implements its behavior.
2. Add `AnchoredRoot`, `ReceiptDisclosure` and `RevocationLocal` to `ScenarioCategory` (`verdict_matrix/src/lib.rs:49`) with serde names `anchored_root`, `receipt_disclosure` and `revocation_local`, and to `as_str` and `FromStr`.
3. Add the three values to the `category` row of `verdict_matrix/SCENARIOS.md` (line 19).
4. Update `manifest.toml`: `scenario_count`, the `[corpus.categories]` counts, `scenario_index_hash` and `corpus_sha256`.
5. Add the `rust-mcp-serve-http` driver entry to `manifest.toml` and its runner under `verdict_matrix/drivers/`, with the IdP stub, introspection stub and fixture definitions above.
6. Register each reason code in the table above in `spec/errors/registry.yaml` in the PR that first emits it, and run `scripts/check-error-urn-registry.py`.
7. Recheck `requires`: drivers that do not implement `rust-mcp-serve-http` must skip these scenarios, not fail them.
8. Remove this staging directory once all three categories have moved.
