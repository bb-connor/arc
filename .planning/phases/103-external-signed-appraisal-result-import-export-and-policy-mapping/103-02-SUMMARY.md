# Summary 103-02

Defined one explicit local policy-mapping contract for imported appraisal
results.

Implemented:

- `RuntimeAttestationImportedAppraisalPolicy` with trusted issuer, trusted
  signer key, verifier-family allowlist, freshness ceilings, maximum effective
  tier, and required portable-claim matches
- explicit `allow`, `attenuate`, and `reject` outcomes over imported signed
  results
- fail-closed handling for missing policy, invalid signature, stale result or
  evidence, unsupported schema or verifier-family mapping, and claim mismatch

This keeps foreign signed appraisal results policy-visible without allowing
them to widen local trust implicitly.
