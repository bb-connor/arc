# chio-recovery

Pure, deterministic recovery explanations and graph planning for Chio. The crate defaults to
`no_std + alloc` and uses portable core/security data types and the pure semantic-contract validator.
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


The classified graph planner accepts explicit registered plans, with up to 16
offers, 8 top-level steps, 32 total nodes and depth 8 under one allowance of at
most 4,096 work units. The semantic graph representation further limits each
registered graph to 16 nodes. Deployments can lower these limits.

- `plan` validates scope, intent, graph identities, dependencies and estimated
  costs, then returns plans by identifier with deterministic topological steps.
  Every step is assessed against the supplied snapshot. A future step never
  supplies missing evidence for a later step.
- Any exhausted limit returns `SearchBoundReached`, the exact limit and a
  `Top` classification, with no partially searched candidates. It makes no
  validity claim about unsearched graphs.
- All input labels contribute to the result classification, including unused
  remedies. Planner results are classified input to an authorized consumer;
  they are not recipient-safe projections or signed materialized offers.
- Candidate scope, workflow, intent and plan identities remain the supplied
  claims. The native consumer must authenticate workflow ownership and recheck
  current authority before materialization. Candidate plans cannot convert into
  recovery grants.
