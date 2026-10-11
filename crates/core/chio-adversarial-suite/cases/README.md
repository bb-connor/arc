# Chio Adversarial Cases

This directory holds malicious-but-well-formed cases consumed by
trust-boundary tests. Every case is a canonical JSON object that validates
against `../schema/case.schema.json` and is deny-asserted by downstream
harnesses.

Case files are grouped by attack class:

- `clock_rewound/`
- `future_dated/`
- `replayed_nonce/`
- `partial_signature/`
- `scope_superset/`
- `revocation_rollback/`
- `anchor_grafted/`
- `sigstore_bundle_payload_mismatch/`

Vector files are stored in these directories. Auto-promoted cases must set
`pending: true` until triaged; pending cases do not count as threat-model
coverage.

The security roadmap also bundles 28 mutation case definitions for flow,
tripwires, temporal correlation, containment, key rotation, the secret broker
and native confinement. They retain the 35 campaign identities from archived
source `cbbba8cf2178cbbdd7b6b38a121e59365eb452ac`. Restored definitions are
pending until their behavioral controls and selected mutations run against the
current source. Historical outcome hashes cannot qualify the restored source.

The broker quota cases now target the composite SQLite authority that owns
authorization, capture and compensation. Their controls verify bounded quota,
idempotent capture, response loss, restart and reservation restoration. Broker
adapters only observe those original decisions.

`scripts/check-security-adversarial-evidence.sh --list-pending` validates the
case inventory and lists the remaining campaigns. Use the existing campaign
and promotion commands to collect caught-only evidence. The release gate still
requires all cases to be complete. Pending definitions are accepted by the raw
loader and excluded from the cross-language verdict manifest; attempting to
convert one into coverage fails closed.
