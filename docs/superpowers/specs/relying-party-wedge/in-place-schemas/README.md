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

| Staged file | Live path | Moved by | Changes |
|---|---|---|---|
| `capability/token.schema.json` | same | the anchored-root change (M1 exchange and admission) | optional signed `root_anchor` (`$ref` to `root_authority/root-anchor.schema.json`); `monetaryAmount.currency` becomes `asset` (moves with the settlement change if that lands first, see below) |
| `receipt/record.schema.json` | same | the committed-receipts change (M1 item 2) | `action.parameter_commitment` and optional `action.parameters_inline` replace `parameters` and `parameter_hash`; `content_commitment` and optional `result_inline` replace `content_hash`; `disclosure` replaces `redaction_mode`; optional `authority` with `tenant_id` forbidden beside it; inline-field coherence rules |
| `receipt/record.schema.json` (continued) | same | the `pdp_decision` change (M2) and the settlement change (M3) | `pdp_decision`, `prevent_external`, `delegated` enum values with their coherence rule and the required `enforcement` block; optional `settlement` block |
| `capability/revocation.schema.json` | same | the provider revocation change (M1 item 5) | `entry_id`, closed `target_kind` (`capability_id`, `root_policy_rule`, `anchor_subject`, `tenant_tag`, `replay_key`) and `target` replace `capability_id`; reconcile with the parallel revocation-root store shape first (spec D17) |
| `capability/grant.schema.json` | same | the settlement change (M3) | `monetaryAmount.currency` becomes `asset` with the closed `iso4217:` / `caip19:` grammar |
| `export/evidence-export-manifest.schema.json` | `spec/schemas/chio-wire/v1/export/evidence-export-manifest.schema.json` (new live file) | the export-profile change (M1 committed receipts, caller profile M2) | full `chio.evidence_export_manifest.v1` shape from `EvidenceExportManifest`, plus `disclosureProfile`, `tenantTag` (required for `caller`) and `artifacts[]` with the closed role set |

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

- Manifest members are camelCase (`disclosureProfile`, `tenantTag`), because
  `EvidenceExportManifest` is `#[serde(rename_all = "camelCase")]`.
- Tags (`tenantTag`, revocation `anchor_subject` and `tenant_tag` targets) are
  the HMAC-SHA256 output as 64 lowercase hex characters.
- A `replay_key` revocation target is the `replay_key_digest` recorded in the
  delegation context.
- New artifact roles are listed in a separate `artifacts` array; each entry's
  file also appears in `files`.

## Checks

The positive receipts of `tests/bindings/vectors/receipt/committed/v1.json`
validate against the staged `record.schema.json`, and its `tenant_id` beside
`authority` case fails it. The committed-receipt vector generator validates
this inside its `check` once both land.
