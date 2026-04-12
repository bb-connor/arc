# Summary 108-03

Closed `v2.24` with qualification and boundary updates across
`crates/arc-cli/tests/receipt_query.rs`, `spec/PROTOCOL.md`,
`docs/WORKLOAD_IDENTITY_RUNBOOK.md`,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`,
`docs/standards/ARC_OAUTH_AUTHORIZATION_PROFILE.md`, and the release-facing
docs.

Implemented:

- mixed-provider qualification now covers the new enterprise verifier family
  on the shared appraisal-result surface
- auth-context regressions now prove runtime-assurance schema and family
  projection end to end
- facility-policy regressions now prove mixed verifier-family provenance
  downgrades allocation to manual review
- milestone closeout and planning-state advance from `v2.24` to `v2.25`

This keeps ARC's public claim honest: broader provider coverage is now real,
but it remains bounded and policy-narrowed rather than ambiently trusted.
