# hello-receipt-verify Architecture Notes

## Module Boundaries

This example owns the minimal offline evidence-verification path. It does not
start trust-control, issue capabilities, run an app, or mint fresh receipts.
Its checked-in `fixtures/minimal-evidence/` directory is the product surface:
a captured evidence export with one tool receipt, one capability-lineage
record, no checkpoints, an explicit `admin_all` read boundary, and an
`export-envelope.json` signed by the committed example seed
`fixtures/kernel.seed`. `verifier-trust.json` pins that seed's public key.
`smoke.sh` copies the fixture into an artifact directory, runs
`chio evidence verify`, generates a compact summary, tampers with a copied
package, and requires the integrity exit class (20).

There is no crate or package-manager manifest. The example depends only on the
workspace `chio` binary and Python's standard library for local artifact
inspection.

## Security And API Constraints

- Preserve this as an offline-only verifier example. Do not add live
  trust-control, app, sidecar, or receipt-minting steps.
- Preserve the checked-in fixture's explicit `admin_all` read boundary as a
  captured operator export. The example verifies that boundary; it does not
  teach implicit cross-tenant reads.
- Preserve manifest-backed tamper detection: changing any covered file must
  make `chio evidence verify` fail.
- Preserve signed artifact compatibility by treating the checked-in evidence
  package as immutable test input unless the export format itself changes;
  regenerate it from `fixtures/kernel.seed` as the README describes.
- The trust file pins the committed seed's key. `verify_artifacts.py` checks
  that the envelope and receipt signers are keys `verifier-trust.json` pins;
  it never takes a key from the package.

## Affected Dependents

`examples/run-hello-smokes.sh` invokes this smoke by name, so it is the direct
dependent gate. `examples/README.md` and `examples/EXAMPLE_SURFACE_MATRIX.md`
describe the same offline-verification surface and need no update unless the
file set or behavior changes.
