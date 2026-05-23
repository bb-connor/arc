# chio-eval-receipt

`chio-eval-receipt` is the reference-verifier crate for
`chio.eval-report.bundle.v1`.

The initial release intentionally ships only the workspace shell and
stable descriptor:

- schema id: `chio.eval-report.bundle.v1`
- planned schema path: `spec/eval/receipt-format.v1.json`
- initial partner lane: METR
- current stage: `p0-placeholder`

The placeholder fails closed: `EvalReceiptSurface::verifier_ready()`
returns `false` until schema validation, bundle verification, and the CLI
land.

Planned follow-up work:

- Export-contract documentation and verdict-matrix mapping.
- Schema validation, signature verification, CLI support, Python binding
  scaffolding, and golden vectors.
- A partner ingest sample under `examples/eval-receipt-ingest/`.
