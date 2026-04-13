# Runtime Attestation Remediation Memo

## Problem

ARC has enough pieces to tell a credible story about verifier-backed runtime assurance, but it does not yet have an end-to-end architecture that makes the current multi-cloud claims literally true.

The core issue is simple: the runtime authorization path still accepts caller-supplied normalized `RuntimeAttestationEvidence` and applies policy to that object directly (`crates/arc-core-types/src/capability.rs:362-385`, `460-556`; `crates/arc-cli/src/issuance.rs:124-149`, `396-430`; `crates/arc-kernel/src/lib.rs:2965-3001`). Concrete verifier adapters do exist for Azure MAA, AWS Nitro, Google Confidential VM, and the bounded enterprise verifier family (`crates/arc-control-plane/src/attestation.rs:49-60`, `65-257`, `1031-1555`), but those adapters are not the only authority that can produce evidence trusted by issuance or governed execution.

As long as a caller can directly provide a plausible `RuntimeAttestationEvidence` object and have the kernel treat it as "trusted evidence" for policy rebinding, ARC cannot honestly claim that runtime assurance is verifier-backed end to end. It can only claim that ARC has verifier adapters and a normalized evidence schema.

## Current Evidence

- ARC already ships concrete verifier adapters:
  - Azure MAA JWT verification with JWT decoding, algorithm checks, key resolution, signature verification, issuer checks, time checks, attestation-type constraints, and optional workload-identity projection (`crates/arc-control-plane/src/attestation.rs:1031-1098`).
  - Google Confidential VM JWT verification with signature verification, issuer checks, audience checks, hardware-model checks, secure-boot checks, and service-account allowlists (`crates/arc-control-plane/src/attestation.rs:1155-1264`).
  - AWS Nitro `COSE_Sign1` verification with algorithm checks, document freshness, PCR checks, nonce checks, debug-mode denial, certificate parsing, certificate-chain anchoring, and signature verification (`crates/arc-control-plane/src/attestation.rs:1283-1555`).
  - Enterprise verifier signed-envelope verification with signer allowlists, age checks, verifier matching, and tier caps (`crates/arc-control-plane/src/attestation.rs:261-404`).

- ARC already ships a canonical appraisal and import-policy layer:
  - appraisal artifacts, result envelopes, import policy, verifier descriptors, reference-value sets, and trust bundles live in `crates/arc-appraisal/src/lib.rs`;
  - imported result evaluation enforces explicit local policy, signature verification, schema checks, result/evidence freshness, trusted issuer/signer checks, verifier-family checks, and required-claim checks (`crates/arc-appraisal/src/lib.rs:1716-1805`).

- ARC already documents a broad supported surface:
  - the runbook says ARC ships Azure/AWS Nitro/Google verifier bridges, signed appraisal reports and results, trust bundles, and explicit verifier rebinding (`docs/WORKLOAD_IDENTITY_RUNBOOK.md:6-27`, `85-94`);
  - the protocol spec says issuance and governed execution treat runtime attestation as trusted evidence, describes the Azure/AWS/Google bridges, and presents appraisal artifacts as the stable adapter boundary (`spec/PROTOCOL.md:726-840`);
  - release qualification and release audit both say the runtime-attestation gap is closed (`docs/release/QUALIFICATION.md:226-231`; `docs/release/RELEASE_AUDIT.md:205-209`).

- ARC already has operator-facing appraisal export/import surfaces, but they currently operate over normalized `RuntimeAttestationEvidence`, not raw attestation statements:
  - the CLI loads a `RuntimeAttestationEvidence` object directly from disk (`crates/arc-cli/src/main.rs:8555-8568`);
  - appraisal export passes that object straight into report generation (`crates/arc-cli/src/main.rs:8582-8605`);
  - trust-control appraisal report generation derives an appraisal from the normalized evidence object and then runs local trust-policy resolution over that same object (`crates/arc-cli/src/trust_control.rs:13205-13254`).

## Why Claims Overreach

- **Verifier output is not the sole runtime authority.** The kernel and issuance paths consume `RuntimeAttestationEvidence` directly. Nothing in those hot paths requires that the object came from `AzureMaaVerifierAdapter`, `AwsNitroVerifierAdapter`, `GoogleConfidentialVmVerifierAdapter`, or `EnterpriseVerifierAdapter` rather than from a caller, wrapper, or test helper (`crates/arc-cli/src/issuance.rs:124-149`, `396-430`; `crates/arc-kernel/src/lib.rs:2965-3001`).

- **Policy rebinding is happening over normalized claims, not over a verifier-issued admission artifact.** `resolve_effective_runtime_assurance` takes `schema`, `verifier`, time bounds, and normalized assertions derived from the carried evidence object, then matches trust rules and potentially upgrades the effective tier (`crates/arc-core-types/src/capability.rs:460-556`). That is a useful policy engine, but it is not an end-to-end verifier pipeline by itself.

- **Appraisal export is not proof that verification happened.** The operator-facing appraisal report path currently appraises an already-normalized evidence object (`crates/arc-cli/src/trust_control.rs:13205-13254`), and the CLI input path expects a `RuntimeAttestationEvidence` JSON or YAML document (`crates/arc-cli/src/main.rs:8555-8605`). That means the report surface is currently closer to "signed analysis of a normalized evidence object" than "signed proof that ARC verified a raw Azure/Google/Nitro attestation statement."

- **JWT trust roots are under-specified.** The Azure and Google bridges verify JWT signatures against supplied or fetched JWKS material, but the runtime story does not yet make the trust root explicit enough. Today there is no single authoritative model for whether trust comes from pinned static keys, OIDC discovery, pinned metadata URLs, pinned JWKS digests, or certificate chains. If ARC wants to claim standards-grade verifier trust roots, it needs one explicit trust model per verifier family.

- **JWT `x5c` handling is not strong enough to support certificate-chain rhetoric.** When a JWK uses `x5c`, ARC extracts the public key from the first certificate but does not validate that certificate chain to a configured root or validate certificate lifecycle or usage semantics in the JWT path (`crates/arc-control-plane/src/attestation.rs:1877-1944`). If the claim is "JWKS-backed JWT verification," that is fine. If the claim is "certificate-chain validated JWT attestation verification," it is not yet true.

- **Imported appraisal results are not runtime admission tokens yet.** ARC can evaluate imported appraisal results under explicit local policy (`crates/arc-appraisal/src/lib.rs:1716-1805`), but the current path returns an import report, not a kernel-consumable verified runtime-attestation record (`crates/arc-cli/src/trust_control.rs:13256-13260`). That makes import evaluation a review/export surface, not an integrated runtime authority.

- **Freshness and replay are only partially modeled.** ARC already checks time windows and max ages, and Nitro supports nonce matching. The runbook is honest that imported appraisal results do not yet have one-time consume or replay-registry semantics (`docs/WORKLOAD_IDENTITY_RUNBOOK.md:52-64`). For strong live-admission claims, ARC needs one unified replay and freshness model across raw verifier evidence, signed imported results, and runtime consumption.

- **Runtime assurance is not yet bound strongly enough to the caller's authenticated runtime identity.** ARC validates workload-identity consistency inside the attestation object and can preserve runtime identity into policy and receipts, but the attestation that drives runtime-assurance tiering is not yet required to be a locally signed verified record bound to the authenticated caller/session at admission time.

## Target End-State

ARC should target a much stricter model:

- High-assurance runtime decisions must depend only on a verifier-backed local admission artifact.
- Raw provider evidence, normalized evidence JSON, and imported foreign results must never be interpreted directly by issuance or the kernel.
- Every accepted attestation must have explicit provenance:
  - verifier family
  - verifier identifier
  - trust-root or trust-bundle identity
  - evidence digest
  - verified-at timestamp
  - evidence freshness window
  - subject binding (`runtime_identity` and/or `workload_identity`)
  - local policy outcome and effective runtime-assurance tier
- The kernel must accept only:
  - a signed local `VerifiedRuntimeAttestationRecord`, or
  - an opaque local record ID resolved from trusted storage.
- Imported appraisal results must be locally re-admitted before they can influence runtime assurance.
- Runtime-assurance claims should then be narrowed to exactly what the runtime path enforces:
  - Azure MAA JWT verification with explicit trust roots;
  - AWS Nitro COSE verification with anchored x509 chain and PCR policy;
  - Google Confidential VM JWT verification with explicit issuer/JWKS/audience policy;
  - enterprise verifier import under explicit signer policy;
  - local runtime enforcement over signed verified records only.

## Required Verifier/Runtime Changes

- **Introduce a first-class verified record type.**
  - Add a new type such as `VerifiedRuntimeAttestationRecord`.
  - Include: `record_id`, `source_kind`, `attestation_schema`, `verifier_family`, `verifier_id`, `adapter`, `evidence_sha256`, `issued_at`, `expires_at`, `verified_at`, subject binding, normalized claims, local rule match, effective tier, and trust-root provenance.
  - Sign the record with a local attestation-verifier authority key, or persist it in local storage and require the kernel to resolve it by ID.
  - Demote the current public `RuntimeAttestationEvidence` object to an internal intermediate shape or raw adapter output. It should not remain a direct runtime-admission input.

- **Create a verifier registry with explicit trust-root modes.**
  - Add a control-plane registry for attestation verifiers, keyed by stable `verifier_id`.
  - Each verifier entry should declare one trust mode:
    - `static_jwks`
    - `oidc_discovery`
    - `x509_roots`
    - `trusted_signer_keys`
  - Each entry should also declare allowed algorithms, metadata source, refresh TTL, fail-closed behavior, and whether nonce/request binding is mandatory.
  - `trusted_verifiers` policy should reference `verifier_id`, not free-form `{schema, verifier}` pairs alone.

- **Make JWT trust roots explicit and auditable.**
  - For Azure and Google, choose and document one primary trust model:
    - either OIDC discovery plus pinned issuer and pinned `jwks_uri`,
    - or operator-provided static JWKS,
    - or x509 chain pinning when `x5c` is present.
  - Do not silently mix trust models.
  - Persist the metadata URL, JWKS digest, `kid`, and resolution timestamp into the verified record.
  - If `x5c` is present and ARC uses it as part of trust, validate the chain, validity windows, key usage, and certificate constraints.
  - If ARC chooses JWKS-over-HTTPS as the trust root, say that clearly and stop implying x509 chain validation for those bridges.

- **Harden AWS Nitro certificate validation.**
  - Keep the existing COSE, PCR, freshness, and nonce checks.
  - Replace or harden the custom certificate-chain logic to enforce:
    - path building against explicit roots,
    - certificate validity windows,
    - CA/basic-constraints semantics,
    - key usage / extended key usage where relevant,
    - signature algorithm constraints.
  - Replace the generic `verifier: "aws-nitro"` string with a configured verifier identity or descriptor ID so receipts and records can point to an actual trust root and operator policy.

- **Cut issuance and kernel over to verified records only.**
  - Change issuance and governed-execution APIs so they accept only a `runtime_attestation_record_id` or a signed `VerifiedRuntimeAttestationRecord`.
  - Remove direct admission of caller-supplied `RuntimeAttestationEvidence` in public request shapes.
  - Require the kernel to verify record signature or local record existence before using any runtime-assurance tier.
  - Require subject binding between the verified record and the authenticated caller/session. At minimum, this should bind to the runtime identity or workload identity preserved by the verifier.

- **Wire imported appraisal results into local admission.**
  - Imported appraisal results should remain separate from local runtime authority until ARC evaluates them under explicit local import policy.
  - After a successful import evaluation, ARC should mint a local verified record with:
    - import-policy outcome,
    - local effective tier,
    - imported signer and issuer provenance,
    - freshness outcome,
    - required-claim checks,
    - attenuation outcome if local policy narrows the tier.
  - The kernel should consume that local record, not the foreign signed result directly.

- **Add replay and challenge binding.**
  - Introduce a replay registry for any evidence used for live admission:
    - JWT `jti` when present,
    - Nitro document digest or nonce,
    - appraisal `result_id` for imported results.
  - Add request- or session-bound challenge semantics for verifier families that support nonce binding.
  - Require imported or enterprise-verifier results used for live admission to carry or reference a local transaction/request binding when the security model needs it.

- **Unify freshness semantics.**
  - Define and store:
    - `evidence_issued_at`
    - `evidence_expires_at`
    - `verified_at`
    - `result_exported_at` for imported results
  - Add a configurable clock-skew allowance.
  - Use per-family freshness rules:
    - Azure/Google: `nbf`, `exp`, optional `iat`, max token age
    - Nitro: document timestamp, max age, future skew, optional nonce freshness
    - enterprise/imported: result age plus underlying evidence age
  - Make freshness failure modes visible in the verified record and receipt metadata.

- **Persist verifier and trust provenance into receipts.**
  - When a request relies on runtime assurance, receipt metadata should capture:
    - verified record ID
    - verifier family
    - verifier ID
    - evidence digest
    - local matched rule
    - local effective tier
    - trust-bundle or JWKS fingerprint where relevant
  - That gives downstream consumers a truthful audit trail of why the stronger runtime posture existed.

- **Separate report/export paths from admission paths.**
  - Keep the operator-facing appraisal report and result artifacts.
  - Add a `verify-then-export` path that starts from raw provider evidence and produces a signed report plus, optionally, a local verified record.
  - Mark the current "export from normalized `RuntimeAttestationEvidence`" path as a developer/test/compatibility path unless or until it is backed by an actual verified record.

## Spec Changes

- Split the runtime-attestation model into three explicit layers:
  - raw attestation statement,
  - locally verified runtime-attestation record,
  - imported foreign appraisal result plus local import decision.

- Update the protocol spec so runtime assurance in issuance and governed execution is based only on locally verified records or locally re-admitted imported results. The current wording in `spec/PROTOCOL.md:726-737` is too loose because it lets "carried attestation evidence" sound authoritative by itself.

- Define verifier trust-root modes formally:
  - `static_jwks`
  - `oidc_discovery`
  - `x509_roots`
  - `trusted_signer_keys`

- Define which claim families are authoritative per provider and which are merely preserved vendor claims.

- Define request binding, replay semantics, and freshness semantics precisely, including:
  - permitted clock skew,
  - one-time consume behavior where applicable,
  - result replay behavior for imported appraisal results.

- Define receipt semantics precisely:
  - receipts prove ARC accepted a locally verified record with specific provenance;
  - receipts do not by themselves prove that raw provider evidence was verified unless the referenced record exists and verifies.

- Update the runbook and qualification docs so they distinguish:
  - "verifier adapter exists",
  - "operator appraisal/export exists",
  - "runtime path is verifier-backed."

## Validation Plan

- **Unit tests for JWT verifier trust roots.**
  - wrong issuer
  - wrong audience
  - stale token
  - future token
  - unsupported algorithm
  - unknown `kid`
  - multiple compatible keys with missing `kid`
  - JWKS rotation
  - `x5c` present but invalid chain
  - metadata URL / issuer mismatch

- **Unit tests for Nitro verification.**
  - malformed COSE
  - invalid algorithm
  - stale document
  - future document
  - PCR mismatch
  - missing PCR
  - nonce mismatch
  - debug-mode rejection
  - certificate-chain rejection on wrong root
  - certificate lifecycle and usage rejection

- **Unit tests for verified record issuance.**
  - raw provider evidence produces a signed verified record
  - record contains verifier/trust-root provenance
  - record tier is `attested` before policy rebinding
  - local policy rebinding happens only after verifier success

- **Unit tests for imported appraisal admission.**
  - no explicit local policy rejects
  - invalid signature rejects
  - stale result rejects
  - stale underlying evidence rejects
  - untrusted issuer rejects
  - untrusted signer rejects
  - unsupported verifier family rejects
  - required-claim mismatch rejects
  - higher foreign tier is attenuated when local policy caps it
  - replayed imported result rejects when replay defense is configured

- **Kernel and issuance end-to-end tests.**
  - handcrafted `RuntimeAttestationEvidence` without a verified record is rejected
  - verified Azure evidence unlocks the intended tier
  - verified Google evidence unlocks the intended tier
  - verified Nitro evidence unlocks the intended tier
  - imported result only works after local re-admission
  - subject mismatch between verified record and authenticated caller is rejected
  - stale verified record is rejected

- **Integration tests for report/export behavior.**
  - raw evidence -> verifier -> verified record -> signed appraisal report
  - verified record -> export-existing-record report
  - imported result -> local import -> verified record -> kernel admission

- **Qualification artifacts.**
  - Add a release-qualification lane that starts with raw provider evidence and ends with runtime admission or denial.
  - Stop using normalized evidence-only fixtures as the primary evidence for multi-cloud runtime-attestation qualification.

## Milestones

1. **Milestone 1: Claim freeze and boundary correction**
   - Narrow public docs until the runtime path is fixed.
   - Update the spec, runbook, and qualification docs to describe the current surface honestly.
   - Mark normalized-evidence export/import paths as operator-reporting or compatibility surfaces, not admission authority.

2. **Milestone 2: Verifier registry and authoritative record type**
   - Add verifier registry, trust-root modes, and `VerifiedRuntimeAttestationRecord`.
   - Implement signed local verified-record issuance for Azure, Nitro, Google, and enterprise verifier.
   - Persist verifier identity and trust provenance.

3. **Milestone 3: Runtime cutover**
   - Change issuance and kernel APIs to accept only verified record IDs or signed records.
   - Remove public direct use of `RuntimeAttestationEvidence` in admission paths.
   - Bind verified records to authenticated caller/session identity.

4. **Milestone 4: Imported-result integration**
   - Turn import evaluation into local verified-record issuance.
   - Add replay controls and request binding where applicable.
   - Integrate trust bundles and verifier descriptors into runtime verifier resolution.

5. **Milestone 5: Qualification and claim restoration**
   - Add end-to-end multi-cloud qualification from raw evidence to runtime enforcement.
   - Restore stronger claims only after the runtime path uses verified records exclusively.

## Acceptance Criteria

- A caller cannot satisfy a `verified` or stronger runtime-assurance policy by directly supplying handcrafted normalized evidence.
- ARC can mint a local verified record only after successful provider-specific verification against explicit configured trust roots.
- Every runtime-assurance decision in issuance and governed execution references a verified record or signed verified-record envelope.
- Imported appraisal results cannot affect runtime assurance until ARC has evaluated them under explicit local import policy and converted them into a local verified record.
- Azure, Nitro, Google, and enterprise-verifier records all carry verifier identity, evidence digest, freshness metadata, and trust-root provenance.
- Replay of imported results or nonce-capable evidence is rejected within the configured replay window.
- Receipt metadata for runtime-assurance decisions points to the exact verified record and local policy rule used.
- Release qualification proves the multi-cloud story end to end from raw provider evidence to runtime allow/deny behavior.
- At that point, the protocol spec, runbook, release audit, and qualification docs all say the same thing and are true in the runtime path.

## Risks/Non-Goals

- **Risk:** OIDC metadata and key rotation can create outage risk if pinning is too strict and refresh semantics are poor.
- **Risk:** Nitro certificate validation is easy to get almost right and still wrong; a weak path builder would create false confidence.
- **Risk:** Subject binding across hosted auth, workload identity, and runtime attestation can become operationally brittle if the binding contract is unclear.
- **Risk:** Replay registries add state and availability requirements to what is currently mostly a pure verification flow.
- **Risk:** Imported appraisal results can encourage over-trust if ARC does not keep local re-admission and attenuation explicit.

- **Non-goal:** universal attestation interoperability across all TEEs or all cloud attestation providers.
- **Non-goal:** proving real-world side effects; this work is about proving runtime posture and local admission truth, not external action truth.
- **Non-goal:** turning appraisal reports into a global transparency log.
- **Non-goal:** widening foreign imported results into local trust automatically; local import policy and local re-admission must stay explicit.
