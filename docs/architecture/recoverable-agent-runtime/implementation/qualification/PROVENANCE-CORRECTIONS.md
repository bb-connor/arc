# Provenance and compatibility corrections

These corrections describe current maintained code. They do not rewrite the
historical naming review, phase packages, source archives or acceptance seals.
New records must bind the reviewed candidate and identify the actual executable
that produced each result.

The original naming cleanup included behavioral and compatibility changes.
Calling that entire delta naming-only was incomplete. The bounded changes are:

| Surface | Meaning of the change |
| --- | --- |
| `crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs` | New signed retention and fee-policy identifiers change signed payload identity. |
| `crates/core/chio-arena/src/promote.rs` | TEE and redaction identifiers in arena frames changed. |
| `crates/sdk/chio-eval-receipt/src/verify.rs` | Fixture-mode receipt hashes changed with regenerated fixtures; old fixture bytes refuse. |
| `examples/reference-swarm/process_matrix_evidence.py` | The public report field became `qualification_complete`. |
| `tests/bindings/vectors/MANIFEST.sha256` | Two preexisting stale active-defense vector hashes were corrected. |
| `.github/workflows/ci.yml` | A source naming gate was added to CI. |
| `fixtures/recovery-product/manifest_builder.py` | The source inventory policy changed substantially; this is qualification tooling behavior, not a label substitution. Version 2 records remain historical. Current bindings explicitly use `chio.source-inventory.v3`, whose secret-shaped inputs have metadata-only coverage. |
| `docs/formal/plan/FV-D1-distributed-revocation-model.md` | Its former manifest anchor no longer names the current key. The current key is `network_transport_assumptions_decision`; the assumption remains scoped and not retired. |

Separately, existing provenance metadata was restored to the base commit's
literal historical values. The restoration affects six `introducedBy` fields
in `spec/schemas/registry.json`, 25 `owned_by`/`closed_by`/`deferred_to` fields in
`spec/security/coverage.yaml`, and 20 `deferred_to` fields in
`spec/security/chio-threat-model.v1.json`. New recovery entries and behavioral
source names remain separate from those historical metadata values. Current
guard exceptions must name the exact existing record, field and value; they
must continue to refuse newly introduced roadmap labels in maintained code.

Historical acceptance anchors such as `recovery_p1_contracts` and
`recovery_p1` stay unchanged inside their sealed records. A current acceptance
map should point to their behavioral successors and pin those successors'
current hashes. An anchor-name crosswalk establishes correspondence; it does
not claim that a historical test executable ran on current bytes.

Explanation acceptance separates bounded label validation and audience
projection from charged label joins, fact verification and dominance work.
The original-basis requirement remains valid when proposed changes leave the
advice identical. Capture and effect liveness belong to native execution tests;
an advisory simulation alone does not establish them.
