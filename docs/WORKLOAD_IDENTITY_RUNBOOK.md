# Workload Identity and Attestation Runbook

This runbook defines the supported operator boundary for Chio workload identity
and attestation trust.

## Supported Surface

- SPIFFE-derived workload identity mapping through
  `runtimeAttestation.workloadIdentity` or a SPIFFE `runtimeIdentity`
- Azure Attestation JWT normalization into Chio `runtimeAttestation`
- AWS Nitro attestation document verification into Chio `runtimeAttestation`
- Google Confidential VM JWT normalization into Chio `runtimeAttestation`
- canonical runtime-attestation appraisal artifacts that separate evidence
  identity, normalized assertions, and vendor-scoped claims
- signed runtime-attestation appraisal reports through
  `chio trust appraisal export` and `POST /v1/reports/runtime-attestation-appraisal`
- signed runtime-attestation appraisal results plus explicit local import
  evaluation through `chio trust appraisal export-result`,
  `chio trust appraisal import`,
  `POST /v1/reports/runtime-attestation-appraisal-result`, and
  `POST /v1/reports/runtime-attestation-appraisal/import`
- signed verifier descriptors, signed reference-value sets, and signed trust
  bundles over the bounded appraisal boundary
- HushSpec runtime-assurance ceilings through
  `extensions.runtime_assurance.tiers`
- Explicit verifier trust and rebinding through
  `extensions.runtime_assurance.trusted_verifiers`

## Appraisal Boundary

Chio now treats verifier output as two related but distinct surfaces:

- `runtimeAttestation`: the bounded evidence Chio carries with governed and
  issuance requests
- `runtime-attestation appraisal`: the canonical adapter-facing contract Chio
  uses to describe verifier family, evidence descriptor, normalized
  assertions, vendor claims, and reason codes

The appraisal contract is intentionally conservative. Vendor-specific claims
remain vendor-scoped, and Chio only normalizes the small set of assertions it
can defend across verifier families.

Operators can export one signed appraisal report over that contract either
locally with:

- `chio trust appraisal export --input <runtime-attestation.json> --policy-file <policy.yaml>`

or remotely through:

- `POST /v1/reports/runtime-attestation-appraisal`

Chio can also exchange one signed appraisal result over that same contract and
evaluate imported results only through one explicit local import policy. The
current shipped import boundary is:

- signature-verified and issuer-provenanced
- constrained to Chio's bounded Azure/AWS Nitro/Google/enterprise-verifier
  bridge inventory
- freshness-bound for both result age and underlying evidence age
- verifier-family and portable-claim mapped through explicit local policy

Chio does not currently implement one-time consume or replay-registry semantics
for imported appraisal results. The current replay defense at this boundary is
explicit signature plus freshness validation.

Chio now also defines one bounded verifier-federation metadata layer over the
same appraisal contract:

- one signed verifier descriptor that names the verifier, family, adapter,
  compatible attestation schemas, trusted signer-key fingerprints, and
  optional reference-value publication URI
- one signed reference-value-set contract with explicit `active`,
  `superseded`, or `revoked` lifecycle state
- one signed trust-bundle contract that versions a descriptor set plus its
  compatible reference-value material

These artifacts are transportable verifier metadata, not automatic trust
admission. Operators may publish or import them, but local `trusted_verifiers`
policy still decides whether runtime assurance is widened.

The signed report captures the canonical appraisal plus the policy-visible
accept or reject outcome Chio derived at export time. It is an operator-facing
evidence artifact, not a claim of generic attestation-result interoperability.

Today Chio ships three concrete verifier families against that boundary:

- Azure MAA JWT evidence with optional SPIFFE workload-identity projection
- AWS Nitro `COSE_Sign1` attestation documents with anchored certificate
  trust, `SHA384` PCR comparison, freshness validation, optional nonce
  matching, and debug-mode denial by default
- Google Confidential VM JWT evidence with OpenID metadata and `JWKS`
  resolution, `RS256` signature verification, audience pinning, hardware-model
  allowlists, secure-boot enforcement, and conservative normalization of the
  resulting verifier output

## Trust Policy Shape

```yaml
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
      verified:
        minimum_attestation_tier: verified
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 300
    trusted_verifiers:
      azure_contoso:
        schema: chio.runtime-attestation.azure-maa.jwt.v1
        verifier: https://maa.contoso.test
        verifier_family: azure_maa
        effective_tier: verified
        max_evidence_age_seconds: 120
        allowed_attestation_types: [sgx]
      google_cvm_prod:
        schema: chio.runtime-attestation.google-confidential-vm.jwt.v1
        verifier: https://confidentialcomputing.googleapis.com
        verifier_family: google_attestation
        effective_tier: verified
        max_evidence_age_seconds: 120
        allowed_attestation_types: [confidential_vm]
        required_assertions:
          hardwareModel: GCP_AMD_SEV
          secureBoot: enabled
```

## Fail-Closed Conditions

- explicit `workloadIdentity` conflicts with raw `runtimeIdentity`
- verifier descriptor is not yet valid, expired, unsigned, or structurally
  incomplete
- trust bundle is not yet valid, expired, unsigned, or structurally incomplete
- trust bundle carries duplicate verifier descriptors or duplicate
  reference-value ids
- trust bundle carries a reference-value set whose verifier family or
  attestation schema is outside the bound descriptor contract
- trust bundle carries ambiguous active reference values for one
  `{descriptorId, attestationSchema}` slot
- superseded reference-value state names an unknown replacement
- attestation evidence is expired or older than the configured verifier rule
- attestation schema or verifier does not match any configured trusted verifier
- attestation claims are missing a required attestation type, carry a
  disallowed type, or fail a configured `required_assertions` match
- Nitro evidence is malformed, uses an unsupported digest or algorithm, fails
  certificate-chain anchoring, carries mismatched PCRs, or mismatches the
  configured nonce
- Google Confidential VM evidence is malformed, signed by an unexpected key,
  carries a mismatched audience, fails secure-boot requirements, or presents
  an unapproved hardware model

## Recovery Guidance

- Verifier mismatch:
  normalize the configured verifier URL exactly to the upstream issuer or
  relying-party string Chio records in `runtimeAttestation.verifier`.
- Stale evidence:
  refresh the upstream attestation and resend the governed or issuance request;
  do not extend `max_evidence_age_seconds` just to bypass freshness checks.
- Verifier outage:
  remove or omit `runtimeAttestation` only for flows that are intentionally
  allowed to fall back to a weaker issuance tier. Requests that require
  stronger runtime assurance should stay denied until verifier service
  recovers.
- Attestation-type mismatch:
  either update the verifier rule to the supported attestation class or fix the
  upstream workload so it emits the intended trusted evidence.
- Nitro measurement mismatch:
  refresh the enclave image or update the configured expected PCRs only after
  confirming the new measurement is an intentional release.
- Nitro chain or nonce mismatch:
  treat it as a trust failure, not a transient transport failure. Reissue the
  attestation document from the enclave and confirm the trusted root and nonce
  configuration are exact.
- Google audience or hardware mismatch:
  confirm the workload is requesting a token for the configured relying party
  and that the verifier rule's `required_assertions` reflect the intended
  production hardware and boot posture exactly.
- Ambiguous or stale trust bundle:
  reject the bundle wholesale, refresh it from the publisher, and do not
  cherry-pick reference values from a partially invalid bundle.
- Descriptor/reference-value mismatch:
  treat it as publisher metadata corruption or version skew. Do not remap the
  verifier family or attestation schema locally just to make the bundle fit.

## Qualification Commands

- `cargo test -p chio-core appraisal -- --nocapture`
- `cargo test -p chio-core trust_bundle -- --nocapture`
- `cargo test -p chio-core runtime_attestation_trust_policy -- --nocapture`
- `cargo test -p chio-policy runtime_assurance_validation -- --nocapture`
- `cargo test -p chio-control-plane azure_maa -- --nocapture`
- `cargo test -p chio-control-plane aws_nitro -- --nocapture`
- `cargo test -p chio-control-plane google_confidential_vm -- --nocapture`
- `cargo test -p chio-control-plane runtime_assurance_policy -- --nocapture`
- `cargo test -p chio-kernel governed_request_denies_untrusted_attestation_when_trust_policy_is_configured -- --nocapture`
- `cargo test -p chio-kernel governed_monetary_allow_rebinds_trusted_attestation_to_verified -- --nocapture`
- `cargo test -p chio-kernel governed_monetary_allow_rebinds_google_attestation_to_verified -- --nocapture`
- `cargo test -p chio-cli --test receipt_query test_runtime_attestation_appraisal_export_surfaces -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_runtime_attestation_appraisal_result_import_export_surfaces -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query test_runtime_attestation_appraisal_result_qualification_covers_mixed_providers_and_fail_closed_imports -- --exact --nocapture`
