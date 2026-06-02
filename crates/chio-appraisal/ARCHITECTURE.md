# chio-appraisal Architecture

## Owner

`chio-appraisal` owns portable runtime-attestation appraisal artifacts and the deterministic marketplace invocation-pricing model derived from those artifacts. It is a pure evaluation crate: it does not fetch evidence, mutate ledgers, settle payments, or read marketplace catalogs.

## Module Boundaries

- `types` defines wire structs, schema constants, appraisal result envelopes, trust-bundle documents, and marketplace-neutral attestation taxonomy.
- `appraisal` derives portable appraisal artifacts from verified runtime evidence and evaluates imported signed appraisal results against local policy.
- `artifact_inventory` publishes static inventories for supported verifier families, normalized claims, and reason taxonomy.
- `descriptor` signs and verifies descriptor, reference-value, and trust-bundle export envelopes.
- `validate` enforces descriptor, reference-value, and trust-bundle structural invariants before signed artifacts are trusted.
- `marketplace_pricing` computes deterministic per-invocation prices from a manifest base price plus tenant reputation tier.

## Pain Points

- The pricing helper currently treats currency as an opaque string. Catalog callers can compute and persist prices with empty, padded, lowercase, or otherwise non-canonical currency codes.
- The existing `compute_marketplace_invocation_price` API returns a value rather than a `Result`, so hardening the public function directly would break current callers.
- Downstream marketplace CLI code persists computed prices into install records, so pricing input validation has to fail closed before those records are written.

## Security And API Constraints

- Appraisal derivation and pricing must remain deterministic pure functions of their explicit inputs.
- Imported appraisal evaluation must not widen local runtime-assurance policy.
- Signed appraisal, descriptor, reference-value, and trust-bundle artifacts must keep canonical JSON byte stability.
- Marketplace prices must use stable minor-unit integer arithmetic and must not introduce floating-point rounding.
- Public API compatibility must be preserved. New checked APIs may be added, but existing call signatures should not be removed or changed without approval.

## Affected Dependents

`crates/chio-cli/src/market.rs` consumes marketplace pricing for `guard market list`, `info`, and `install`. If pricing validation is added, the CLI catalog path needs a minimal transitive update so malformed catalog prices fail closed instead of being displayed or persisted.

## Planned Improvement

Add checked pricing constructors and a checked invocation-pricing API that validates tenant id and ISO-style uppercase currency codes. Keep the existing unchecked compute function for compatibility, then move the CLI marketplace catalog path onto the checked API.
