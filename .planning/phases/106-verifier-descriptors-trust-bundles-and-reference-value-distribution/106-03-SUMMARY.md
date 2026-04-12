# Summary 106-03

Documented the bounded consumption rules for verifier descriptors, signed
reference-value sets, and signed trust bundles across the public ARC contract.

Updated:

- `spec/PROTOCOL.md`
- `docs/WORKLOAD_IDENTITY_RUNBOOK.md`
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
- release qualification and release-boundary docs

The public claim is now explicit: ARC ships portable signed verifier metadata
over the bounded appraisal contract, but operators must still apply explicit
local policy before widening trust.
