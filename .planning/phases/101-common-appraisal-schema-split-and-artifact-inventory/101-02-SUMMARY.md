# Summary 101-02

Inventoried the shipped verifier families and mapped them into one portable
appraisal artifact boundary.

Implemented:

- `runtime_attestation_appraisal_artifact_inventory()` covering Azure MAA, AWS
  Nitro, and Google Confidential VM
- per-provider inventory entries for attestation schema, artifact schema,
  verifier family, adapter name, vendor claim namespace, and normalized claim
  keys
- test coverage proving the inventory includes the currently shipped bridge
  families and their portable mapping metadata

This makes migration explicit instead of silently dropping provider-specific
semantics during the common-artifact transition.
