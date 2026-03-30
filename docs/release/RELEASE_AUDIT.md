# Release Audit

## Scope

This audit tracks the current ARC production-candidate surface described in
[RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md).

It is a repo-local go/no-go record, not a substitute for observing hosted CI
and release-qualification workflows after merge.

## Decision

**Decision:** Local go, external release hold for the current ARC candidate,
with `v2.9` economic-interop, `v2.10` underwriting, `v2.11` portable
credential interop, `v2.12` workload-identity/attestation, and `v2.13`
portable-credential lifecycle additions, plus the `v2.14` verifier-side
OID4VP surface, plus `v2.15` multi-cloud attestation appraisal additions and
`v2.16` enterprise-IAM profile additions, locally verified and non-blocking to
the existing publication hold, plus the `v2.17` governed public
certification-marketplace surface, plus the `v2.18` credit, exposure, and
capital-policy surface, plus the `v2.19` bonded-execution simulation and
operator-control surface, plus the `v2.20` liability-market and claims-network
surface, plus the `v2.21` standards-native authorization and
credential-fabric surface, plus the `v2.22` wallet exchange, identity
continuity, and bounded sender-constrained authorization surface.

Meaning:

- release inputs, workspace correctness, dashboard packaging, SDK packaging,
  live conformance, and repeat-run clustered trust qualification are green
- operator deployment, backup/restore, upgrade/rollback, and observability
  contracts are documented explicitly
- protocol documentation now describes the shipped `v2` surface instead of an
  aspirational draft
- ARC is now the primary package, CLI, SDK, schema, and operator identity
  where the rename contract says it should be
- standards and launch artifacts exist for receipts and portable trust, plus a
  GA checklist, partner proof package, and explicit risk register
- hosted `CI` and `Release Qualification` workflows are still required before
  tagging a release from `main`

**Local qualification date:** 2026-03-30

## Evidence

Primary local qualification commands:

- `./scripts/ci-workspace.sh`
- `./scripts/check-sdk-parity.sh`
- `./scripts/qualify-release.sh`
- `cargo clippy -p arc-cli -- -D warnings`
- `cargo test -p arc-cli --test provider_admin trust_service_health_reports_enterprise_and_verifier_policy_state -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_admin_health_reports_runtime_state -- --nocapture`
- `cargo test -p arc-cli --test certify certify_registry_remote_publish_list_get_resolve_and_revoke_work -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_metered_billing_reconciliation_report_and_action_endpoint -- --exact`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact`
- `cargo test -p arc-core underwriting -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_appeal_and_supersession_lifecycle -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_requires_anchor -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_rejected_appeal_cannot_link_replacement_decision -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_with_mixed_currency_exposure_withholds_premium -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_decision_list_partitions_premium_totals_by_currency -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_decision_links_failed_settlement_evidence -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_simulation_report_surfaces -- --exact`
- `cargo test -p arc-core credit -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_credit_backtest_report_surfaces_drift_and_failure_modes -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_provider_risk_package_export_surfaces -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query credit_bonded_execution -- --nocapture`
- `cargo test -p arc-cli --test receipt_query liability_provider -- --nocapture`
- `cargo test -p arc-cli --test receipt_query liability_market -- --nocapture`
- `cargo test -p arc-cli --test receipt_query liability_claim -- --nocapture`
- `cargo test -p arc-cli --test passport passport_public_holder_transport_fetch_submit_and_fail_closed_on_replay -- --nocapture`
- `cargo test -p arc-cli --test passport passport_external_http_issuance_and_verifier_roundtrip_is_interop_qualified -- --nocapture`
- `cargo test -p arc-cli --test passport passport_oid4vp_request_uri_and_direct_post_roundtrip_is_replay_safe -- --nocapture`
- `cargo test -p arc-cli --test passport passport_oid4vp_cli_holder_adapter_supports_same_device_and_cross_device_launches -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_metadata_rejects_public_status_distribution_without_cache_ttl -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_metadata_endpoints_require_signing_key_configuration -- --nocapture`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_stale_or_mismatched_identity_assertion -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime -- --exact --nocapture --test-threads=1`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint -- --exact --nocapture --test-threads=1`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls -- --exact --nocapture --test-threads=1`
- `cargo test -p arc-core appraisal -- --nocapture`
- `cargo test -p arc-core runtime_attestation_trust_policy -- --nocapture`
- `cargo test -p arc-policy runtime_assurance_validation -- --nocapture`
- `cargo test -p arc-control-plane azure_maa -- --nocapture`
- `cargo test -p arc-control-plane aws_nitro -- --nocapture`
- `cargo test -p arc-control-plane google_confidential_vm -- --nocapture`
- `cargo test -p arc-control-plane runtime_assurance_policy -- --nocapture`
- `cargo test -p arc-kernel governed_request_denies_untrusted_attestation_when_trust_policy_is_configured -- --nocapture`
- `cargo test -p arc-kernel governed_monetary_allow_rebinds_trusted_attestation_to_verified -- --nocapture`
- `cargo test -p arc-kernel governed_monetary_allow_rebinds_google_attestation_to_verified -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_runtime_attestation_appraisal_export_surfaces -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_check_emits_signed_pass_artifact_and_report -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_marketplace_search_transparency_consume_and_dispute_work -- --exact --nocapture`

Primary release artifacts:

- `target/release-qualification/conformance/wave1/report.md`
- `target/release-qualification/conformance/wave2/report.md`
- `target/release-qualification/conformance/wave3/report.md`
- `target/release-qualification/conformance/wave4/report.md`
- `target/release-qualification/conformance/wave5/report.md`
- `target/release-qualification/logs/trust-cluster-repeat-run.log`

Primary release docs:

- [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md)
- [QUALIFICATION.md](QUALIFICATION.md)
- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md)
- [OBSERVABILITY.md](OBSERVABILITY.md)
- [GA_CHECKLIST.md](GA_CHECKLIST.md)
- [PARTNER_PROOF.md](PARTNER_PROOF.md)
- [ECONOMIC_INTEROP_GUIDE.md](../ECONOMIC_INTEROP_GUIDE.md)
- [CREDENTIAL_INTEROP_GUIDE.md](../CREDENTIAL_INTEROP_GUIDE.md)
- [WORKLOAD_IDENTITY_RUNBOOK.md](../WORKLOAD_IDENTITY_RUNBOOK.md)
- [RISK_REGISTER.md](RISK_REGISTER.md)
- [ARC_RECEIPTS_PROFILE.md](../standards/ARC_RECEIPTS_PROFILE.md)
- [ARC_PORTABLE_TRUST_PROFILE.md](../standards/ARC_PORTABLE_TRUST_PROFILE.md)
- [README.md](../../README.md)
- [PROTOCOL.md](../../spec/PROTOCOL.md)

## Findings Closure

| Former gap | Release disposition |
| --- | --- |
| release-input drift and generated artifacts in source control | closed through package guards, ignore rules, and release-input checks |
| ad hoc qualification and packaging confidence | closed through one scripted release lane plus focused dashboard and SDK package checks |
| operator deployment and upgrade tribal knowledge | closed through the runbook and repeatable smoke checks |
| opaque production diagnostics | closed for the supported surface through trust-control and hosted-edge health/admin contracts plus operator reporting |
| protocol doc drift | closed through a shipped `v2` protocol document aligned to repository behavior |
| launch/standards ambiguity | closed through standards profiles, GA checklist, and explicit risk register |
| economic interop legibility for IAM/finance/partner reviewers | closed for the shipped local surface through the authorization-context report, metered-billing reconciliation report, and focused interop guide |
| enterprise IAM review still depended on ARC-specific explanation rather than machine-readable profile artifacts and end-to-end receipt trace packs | closed for the shipped local surface through authorization-profile metadata, authorization-review-pack exports, fail-closed assurance and call-chain projection validation, and focused qualification coverage |
| underwriting decisioning legibility and operator what-if inspection | closed for the shipped local surface through deterministic decision reports, signed lifecycle artifacts, appeal handling, and non-mutating simulation |
| post-audit underwriting contract defects on fail-closed issue behavior, appeal invariants, evidence linkage, and currency truth | closed through the remediation sweep that tightened trust-control error propagation, rejected contradictory appeal resolution, withheld mixed-currency premium amounts, partitioned premium totals by currency, and added regression coverage |
| portable credential interop remained a standards-alignment claim without one concrete external-client proof | closed for the shipped local surface through the raw-HTTP issuer/challenge qualification lane and focused credential interop guide |
| portable credential lifecycle, type metadata, and verifier-facing status semantics remained only partially explicit | closed for the shipped local surface through projected SD-JWT VC metadata, portable issuer `JWKS`, TTL-backed lifecycle distribution and public resolution, explicit `stale` fail-closed semantics, and focused qualification coverage over `active`, `stale`, `superseded`, and `revoked` states |
| verifier portability still lacked one supported OID4VP bridge and public verifier trust bootstrap | closed for the shipped local surface through signed `request_uri` requests, same-device and cross-device launch artifacts, ARC verifier metadata, trusted-key `JWKS` rotation semantics, and focused passport regressions |
| workload identity and verifier-backed attestation trust remained normalized evidence only, without explicit rebinding and operator failure guidance | closed for the shipped local surface through SPIFFE workload mapping, the Azure MAA bridge, trusted-verifier rebinding policy, fail-closed governed-runtime enforcement, and the workload-identity runbook |
| the verifier boundary remained Azure-shaped and lacked one signed operator-facing appraisal artifact | closed for the shipped local surface through the canonical appraisal contract, Azure/AWS Nitro/Google verifier bridges, policy-aware rebinding, and the signed runtime-attestation appraisal export surface |
| certification discovery remained operator-scoped and under-documented relative to the research marketplace direction | closed for the shipped local surface through versioned evidence profiles, public publisher metadata, public search and transparency feeds, explicit dispute semantics, and policy-bound consume flows with stale or mismatched metadata failing closed |
| underwriting still stopped short of replayable credit qualification and one provider-facing capital review package | closed for the shipped local surface through signed exposure and scorecard artifacts, bounded facility policy, deterministic backtests, and a signed provider-risk package with honest recent-loss history |
| ARC still stopped short of a bounded liability-market proof over provider policy, quote/bind, and claims workflow state | closed for the shipped local surface through curated provider-registry artifacts, provider-neutral quote/bind state, immutable claim/dispute/adjudication artifacts, focused marketplace qualification coverage, and updated partner/release boundary docs |

## Phase 43 Formal/Spec Closure Inventory

This section records the accepted closure boundary for the `v2.8` formal/spec
slice. It is not the final GA decision artifact; it defines what launch claims
phase 44 is allowed to rely on.

| Gap | Launch disposition | Evidence |
| --- | --- | --- |
| executable spec drift versus current `ArcScope` subset behavior | closed in phase 43 | `formal/diff-tests`, `cargo test -p arc-formal-diff-tests` |
| protocol lacked an explicit distinction between formal, empirical, and qualification evidence | closed in phase 43 | `spec/PROTOCOL.md`, this audit, `docs/release/QUALIFICATION.md` |
| Lean root and comments implied stronger proof closure than the repo actually ships | closed in phase 43 | `formal/lean4/Pact/Pact.lean`, `formal/lean4/Pact/Pact/Spec/Properties.lean` |
| standalone Lean proof completion for every current ARC surface | consciously deferred | `formal/lean4/Pact/Pact/Proofs/Monotonicity.lean` still contains `sorry` and is not part of the release gate |
| theorem-prover coverage for governed approvals, payment rails, federation maturity, and runtime assurance | consciously deferred | launch claims rely on runtime tests, integration tests, and qualification rather than Lean proofs |

### Accepted Launch Evidence Boundary

For the current launch candidate, ARC claims:

- executable reference/spec alignment for scope attenuation semantics
- empirical verification for fail-closed kernel and trust-control behavior
- conformance and release-qualification evidence for mediated protocol and
  operator flows

ARC does not currently claim:

- complete theorem-prover coverage for every shipped protocol property
- that standalone Lean proof files are part of the release gate while they
  remain outside the root import surface or contain `sorry`

## Phase 44 Launch Decision

The launch decision is now explicit rather than implied:

| Gate class | Requirement | Status |
| --- | --- | --- |
| local qualification | `./scripts/ci-workspace.sh`, `./scripts/check-sdk-parity.sh`, and `./scripts/qualify-release.sh` green | satisfied |
| launch materials | release, partner, operational, and standards-facing docs updated to the current ARC surface | satisfied |
| hosted publication | hosted `CI` and `Release Qualification` observed green on the candidate commit | pending external observation |

The resulting decision is:

- local technical go for the current ARC candidate
- external release hold until hosted workflow evidence is observed

## Remaining Non-Goals

These are intentionally not blockers for the current ARC production candidate:

- multi-region or consensus trust replication
- permissionless or auto-trusting certification marketplace semantics
- automatic SCIM lifecycle management
- synthetic cross-issuer passport trust aggregation
- theorem-prover completion for every protocol claim
- performance-first rewrite work

## Procedural Note

This audit was produced from the local development environment.

It does not claim that GitHub Actions has already run on the updated
workflows. The repository is ready for that hosted verification, and the
explicit launch decision above keeps external release publication on hold until
those workflow results are observed.
