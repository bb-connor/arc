# Staged in-place v1 schema targets

These files are complete target versions of existing `chio-wire/v1` schemas.
They are not live. `crates/core/chio-core-types/tests/wire_protocol_schema.rs`
validates live serialization against the live files, and the four-language
codegen derives from `spec/schemas/chio-wire/v1/`, so each file moves into
place only with the code change that changes the bytes.

Each file started from the live file at `main` when it was staged. Paths
mirror `spec/schemas/chio-wire/v1/`, so relative `$ref`s (for example
`../root_authority/root-anchor.schema.json`) resolve once the file is in place.
New members carry "Introduced with ..." in their `description`, naming the
PROTOCOL section of the change that introduces them.

## Move-in rule

The implementing PR replaces the live file with the staged file in the same
commit (`git mv` over the live path), refreshes `spec/schemas/MANIFEST.sha256`,
regenerates code in all four languages (`cargo xtask codegen --lang
rust|python|ts|go`) and makes `wire_protocol_schema.rs` green against the new
bytes. Nothing keeps the old shape: the live file is replaced, not versioned.
Before moving a file, re-diff it against the live file on `main`; a live change
made after staging is carried into the staged file first.

`capability/examples/` holds pinned instances for `revocation.schema.json`:
one valid `anchor_subject` (`st1`) and one valid `tenant_tag` (`tt1`) entry,
and the two crossed-prefix entries, which fail at `/target` on `pattern`
(`invalid-expectations.json`). They move to
`spec/schemas/chio-wire/v1/capability/examples/` with the schema, and the
implementing PR runs them through the schema example check and pins the same
four cases against the revocation decoder.

| Staged file | Live path | Moved by | Changes |
|---|---|---|---|
| `capability/token.schema.json` | same | the anchored-root change (M1 exchange and admission) | optional signed `root_anchor` (`$ref` to `root_authority/root-anchor.schema.json`); `monetaryAmount.currency` becomes `asset` (moves with the settlement change if that lands first, see below) |
| `receipt/record.schema.json` | same | the committed-receipts change (M1 item 2) | `action.parameter_commitment` and optional `action.parameters_inline` replace `parameters` and `parameter_hash`; `content_commitment` and optional `result_inline` replace `content_hash`; `disclosure` replaces `redaction_mode`; optional `authority` with `tenant_id` forbidden beside it; inline-field coherence rules |
| `receipt/record.schema.json` (continued) | same | the `pdp_decision` change (M2) and the settlement change (M3) | `pdp_decision`, `prevent_external`, `delegated` enum values with their coherence rule and the required `enforcement` block; optional `settlement` block |
| `capability/revocation.schema.json` (deleted; now `root_authority/revocation-entry.schema.json` and `root_authority/revocation-admin-request.schema.json`) | same | the provider revocation change (M1 item 5) | `entry_id`, closed `target_kind` (`capability_id`, `root_policy_rule`, `anchor_subject`, `tenant_tag`, `replay_key`) and `target` replace `capability_id`; reconcile with the parallel revocation-root store shape first (spec D17) |
| `capability/grant.schema.json` | same | the settlement change (M3) | `monetaryAmount.currency` becomes `asset` with the closed `iso4217:` / `caip19:` grammar |
| `export/evidence-export-manifest.schema.json` | `spec/schemas/chio-wire/v1/export/evidence-export-manifest.schema.json` (new live file) | the export-profile change (M1 committed receipts, caller profile M2) | full `chio.evidence_export_manifest.v1` shape from `EvidenceExportManifest`, plus `disclosureProfile`, `tenantTags` (required for `caller`) and `artifacts[]` with the closed role set |

`record.schema.json` collects changes from three milestones. A PR that moves
it before the later changes land removes the members it does not implement
(`enforcement`, the `pdp_decision` values and rule, `settlement`) from the
copy it moves, and leaves them here for the later PR.

`monetaryAmount` appears in `token.schema.json` and `grant.schema.json` and
mirrors one Rust type, so both move with the settlement change. The live
`agent/governed-transaction-intent.schema.json`,
`capability/cumulative-approval-root.schema.json` and
`kernel/caller_delivery_report.schema.json` also carry a `currency` member;
the settlement PR checks whether each mirrors `MonetaryAmount` and changes it
in the same PR.

## Choices made here that the spec leaves open

- Manifest members are camelCase (`disclosureProfile`, `tenantTags`), because
  `EvidenceExportManifest` is `#[serde(rename_all = "camelCase")]`.
- Tags are keyed index values (PROTOCOL 5.6.8). The manifest's `tenantTags`
  holds typed values `{key_id, value}`, one per loaded generation; a revocation
  `anchor_subject` target uses the string form `st1.<hex key_id>.<hex value>`
  and a `tenant_tag` target uses `tt1.<hex key_id>.<hex value>`. Each target
  kind accepts only its own prefix. The generated bindings do not enforce the
  `if`/`then` branches that bind the prefix to the kind, so the revocation
  decoder parses the target with `KeyedIndexValue::parse_string_form` under the
  purpose of its `target_kind` (`SubjectTag` or `TenantTag`) and refuses the
  other prefix.
- A `replay_key` revocation target is the `replay_key_digest` recorded in the
  delegation context.
- New artifact roles are listed in a separate `artifacts` array; each entry's
  file also appears in `files`.

## Schema-only rejections the M1 decoders must enforce

The generated Rust bindings in `crates/core/chio-core-types/src/_generated/`
enforce unknown-member rejection, closed enums, required members, string
patterns and string lengths. They do not enforce `const`, `maximum`,
`minItems`, `maxItems`, or the `if`/`then`/`else`, `not` and conditional
`oneOf` rules, so the following invalid examples under
`spec/schemas/chio-wire/v1/root_authority/examples/invalid/` decode through
the generated types. Each is a rule the hand-written decoder or load check of
that type must enforce in M1. The list is pinned by
`crates/core/chio-core-types/tests/root_authority_generated_examples.rs`; a
generator change that starts enforcing one of these removes it from both.

| Example | Rule the M1 decoder enforces |
|---|---|
| `delegation-context.id-jag-without-provider-record`, `delegation-context.id-jag-without-identity-digest` | provider-backed kinds carry `provider_record_id` and `provider_identity_digest` |
| `delegation-context.static-bearer-with-provider-record` | non-provider kinds carry neither provider member |
| `delegation-context.id-jag-without-kid`, `delegation-context.oidc-jwt-without-kid` | `oauth_id_jag`, `entra_jwt`, `entra_agent_id` and `oidc_jwt` carry `key_snapshot_digest`, `kid`, `alg` and `artifact_digest` |
| `delegation-context.introspection-with-artifact-digest`, `delegation-context.local-as-with-artifact-digest`, `delegation-context.operator-key-with-artifact-digest` | `artifact_digest` only on `oauth_id_jag`, `entra_jwt`, `entra_agent_id` and `oidc_jwt` |
| `delegation-context.static-bearer-with-kid`, `delegation-context.static-bearer-issuer`, `delegation-context.static-bearer-claims` | `operator_static_bearer`: issuer `urn:chio:operator`, no key or artifact members, no claims |
| `delegation-context.retained-on-static-bearer` | `artifact_retained` is `false` except for `oauth_id_jag` |
| `delegation-context.entra-claim-on-id-jag` | `azp`, `appid`, `oid`, `tid` only for the Entra kinds |
| `delegation-context.subject-tenant-salt-ref` | subject `salt_ref` is `anchor.sub`, tenant `salt_ref` is `anchor.tenant` |
| `enterprise-provider-identity.both-key-sources`, `.no-key-source`, `.introspection-with-jwks-url` | `oidc_jwks` has exactly one of `jwks_url` and `jwks`; `oauth_introspection` has `introspection_url` and neither |
| `idp-key-snapshot.rsa-without-modulus`, `idp-key-snapshot.ec-without-y` | per-`kty` JWK members (RSA `n`/`e`, EC `crv`/`x`/`y`, OKP `crv`/`x`) |
| `idp-key-snapshot.ec-with-ed25519-curve`, `idp-key-snapshot.okp-with-p256-curve` | `crv` matches `kty` (EC: `P-256`, `P-384`, `P-521`; OKP: `Ed25519`; RSA: none) |
| `presentation.too-many-ancestors` | at most 16 ancestors |
| `root-policy.clock-skew-61` | `max_clock_skew_secs` at most 60 |
| `root-policy.disclosure-default-inline` | `disclosure.default` is `committed` |
| `root-policy.id-jag-without-provider-record`, `.id-jag-without-identity-digest` | provider-backed rules carry both provider members in `match` |
| `root-policy.id-jag-without-allowed-algs`, `root-policy.introspection-with-allowed-algs` | JWT kinds carry `allowed_algs`; `oauth_introspection` rules do not |
| `root-policy.static-bearer-with-provider-record`, `root-policy.local-as-with-allowed-algs` | non-provider kinds carry no provider members, `allowed_algs` or `idp_scope_projection` |
| `root-policy.static-bearer-without-principal`, `root-policy.principal-on-entra` | `principal` and `tenant_value` exactly on `operator_static_bearer` |
| `root-policy.entra-max-assertion-lifetime` | no `max_assertion_lifetime_secs` on the Entra kinds |
| `root-policy.retain-artifact-on-entra` | `retain_idp_artifact` only on `oauth_id_jag` |
| `root-policy.entra-claim-on-id-jag` | Entra claims recorded or matched only by Entra rules |
| `root-policy.too-many-exchange-keys` | at most 16 exchange keys |
| `verifier-trust.empty-kernel-keys` | at least one kernel, exchange and root policy key |

The generated `schema` members are plain strings (the `const` is dropped), so
the M1 decoder of each type also checks its `schema` value. The generated maps
(`disclosure.tools`, `idp_scope_projection`, `idp_keys`, `pep_keys`) are
`HashMap`s; signed and content-addressed bodies are always produced through
canonical JSON, never by serializing a generated value directly.

## Checks

The positive receipts of `tests/bindings/vectors/receipt/committed/v1.json`
validate against the staged `record.schema.json`, and its `tenant_id` beside
`authority` case fails it. The committed-receipt vector generator validates
this inside its `check` once both land.
