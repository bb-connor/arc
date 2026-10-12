# chio-appraisal architecture

## Responsibility and boundary

This crate owns appraisal projections, attestation-record authentication,
signed descriptor/reference-value/trust-bundle artifacts, import policy
reports, and marketplace invocation pricing. It stores no evidence and performs
no network I/O. Applications supply evidence, authority pins, policy, and time.

An appraisal's projected verdict describes carried fields. Only the explicit
signed-record boundary can authenticate an authority's assertions for local
assurance promotion. Hardware evidence verification, authority authorization,
revocation, and live challenge binding are supplied by the surrounding system.

## Structure

| Module | Responsibility |
| --- | --- |
| `types` | Schema constants, appraisal/import records, descriptors and errors. |
| `appraisal` | Claim projection, result IDs, vocabulary helpers and import evaluation. |
| `attestation_verification` | Unsigned observation and pinned signed-record boundaries. |
| `descriptor` | Constructs and verifies signed artifact envelopes. |
| `validate` | Validity, uniqueness, schema/family and cross-artifact constraints. |
| `artifact_inventory` | Supported bridges, claim vocabulary and reason taxonomy. |
| `marketplace_pricing` | Checked invocation prices and fiscal discount adapters. |

`marketplace_pricing` is a public module. Other modules expose their public
items through root re-exports. Shared canonical, capability, crypto, receipt,
and error APIs come from `chio-core-types`.

## Data and control flow

`derive_runtime_attestation_appraisal` dispatches on the four supported schemas.
Each projection copies selected vendor claims into normalized assertions and
retains vendor-specific claims. Unknown schemas return `UnsupportedSchema`.
Derivation itself performs no authority-signature or hardware-quote check.

`verify_signed_runtime_attestation_record` compares the envelope signer to a
caller-provided key pin, verifies the envelope, then builds the record.
Record construction derives claims, projects workload identity, and evaluates
local trust policy. Without configured rules, valid evidence remains locally
unaccepted with effective tier `None`. The unsigned entry point rejects a
record that would become locally accepted.

Imported results pass through `evaluate_imported_runtime_attestation_appraisal`.
It collects reasons from signature/schema/family mismatches, age limits,
exporter acceptance, and populated local policy restrictions. Any rejection
reason sets tier `None`; a maximum-tier cap can instead produce `Attenuate`.
Result IDs derive from SHA-256 over canonical result content.

## Trust and invariants

Import policy must be explicit. Issuer, signer-key, verifier-family, age, and
claim filters apply when configured; empty individual allow-lists do not each
force rejection. Age calculations use saturating subtraction, so callers
must account for their own clock and issuance policy.

Signed descriptor helpers validate the artifact and its envelope signature
and validity window. Their verifier uses the carried envelope key, with no
independent pin argument. Trust-bundle validation requires descriptors, unique
IDs, valid nested signatures, family/schema agreement, known successors, and
at most one active reference-value slot per descriptor/schema. Applications authorize
bundle publishers and nested signers independently.

`compute_checked_marketplace_invocation_price` validates nonblank, unpadded
tenant IDs and three uppercase ASCII currency letters, then applies the fixed
0/5/10/20 percent tier discounts with integer truncation. Zero prices remain
zero. Currency validation checks shape rather than membership in a currency
registry. Fiscal pricing resolves governed discounts, explicit fallback, or
denial and uses checked arithmetic. The compatibility helper relies on caller
validation; callers establish the reputation tier and persist pricing evidence.

## Dependencies

`chio-core-types` supplies canonical signing, attestation/workload evidence,
trust policy, and `SignedExportEnvelope`. `chio-fiscal` resolves governed
marketplace discounts. Serde defines portable records; `serde_json` carries
vendor claim values and canonical ID inputs. `thiserror` defines typed pricing
and attestation verification errors. No Cargo features are declared.

## Verification

Use `cargo test -p chio-appraisal`.
`tests/authentication.rs` checks unsigned promotion rejection, signer pins,
field tampering, freshness, and identity binding. `tests.rs` covers all four
claim projections, invalid signed descriptors/reference values, ambiguous active
trust-bundle entries, import signature rejection, local attenuation, and age
limits. Pricing tests cover tier discounts, zero prices, upper monetary bounds,
input validation, and fiscal discount arithmetic. The public integration smoke
test checks the vocabulary schema contract.

[README](README.md) · [Underwriting](../chio-underwriting/README.md)
