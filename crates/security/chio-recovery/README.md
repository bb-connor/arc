# chio-recovery

Pure, deterministic recovery explanations for Chio. The crate defaults to
`no_std + alloc` and depends only on the portable core and security data types.
Its additive `std` feature adds no runtime, storage, transport, clock, signer or
random-number source.

Every input is an untrusted claim. Callers supply the observation time, the
selected trust roots and the recipient's clearance. An explanation cannot
allocate a native operation, dispatch a connector, close an admission intent,
consume a grant or release protected bytes; those stay in the kernel's
admission and capture path.

- `evaluate_explanation` assesses each task-satisfying registered remedy against
  the snapshot under a fixed work allowance. Exhausting the allowance or the
  offer limit reports `SearchBoundReached` with a `Top` classification, never
  `NoRegisteredRemedy`.
- `project_explanation` filters facts and templates to the recipient's clearance
  before searching, so hidden candidates never change public counts, rankings,
  exhaustion or deadlines.
- `prepare_explanation_report` builds the recipient view and the classified
  report, each from one evaluation under half the allowance.
- `verify_explanation_report` binds the verifier's expected key, trust domain,
  issuer, scope, deployment, policy, contract, intent and limits, the validity
  interval and the signature, then recomputes the report from separately
  authorized inputs. `verify_explanation_view` checks projection provenance only.

Signed reports and views use their own signature domains and have no conversion
into `SignedRecoveryGrant` or `SignedDisclosureGrant`.
