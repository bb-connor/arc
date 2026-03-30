# ARC Partner Proof Package

**Prepared:** 2026-03-30  
**Surface:** `v2.22 Wallet Exchange, Identity Assertions, and Sender-Constrained Authorization`

This document is the compact partner/security-review package for ARC's current
launch candidate. It is derived from the same local evidence set used by
[RELEASE_AUDIT.md](RELEASE_AUDIT.md) and
[QUALIFICATION.md](QUALIFICATION.md).

## Current Decision

Local technical evidence says **go** for the current ARC candidate. External
tag/publication remains **on hold** until hosted `CI` and `Release
Qualification` workflow results are observed on the candidate commit.

## What Partners Can Rely On

- capability-scoped mediation, fail-closed guard evaluation, and signed
  receipts
- truthful governed approval, payment, settlement, and reconciliation
  semantics
- derived authorization-context reports that map governed receipts into
  standards-legible authorization details and delegated transaction context
- machine-readable authorization-profile metadata and reviewer-pack exports
  that tie the enterprise IAM projection back to typed governed transaction
  metadata and full signed receipt truth
- portable-trust artifacts built on `did:arc`, ARC-primary passport/verifier
  schemas, certification discovery, and conservative imported-trust handling
- governed public certification marketplace metadata, search, transparency,
  dispute, and consume surfaces that preserve operator provenance and keep
  listing visibility separate from runtime admission
- one qualified portable credential family over OID4VCI-compatible issuer
  metadata, with a native `AgentPassport` lane, projected
  `application/dc+sd-jwt` and `jwt_vc_json` lanes, portable issuer `JWKS`,
  portable type metadata, and read-only TTL-backed lifecycle distribution or
  public resolution with explicit fail-closed `stale` state
- one qualified verifier and holder path over that portable surface, with one
  transport-neutral wallet exchange descriptor and canonical transaction
  state, one optional verifier-scoped identity assertion continuity lane,
  same-device and cross-device launch artifacts, public challenge fetch and
  response submit routes, and one bounded hosted sender-constrained
  continuation contract over DPoP, mTLS thumbprint binding, and one
  attestation-confirmation profile
- signed insurer-facing behavioral-feed exports derived from canonical receipt,
  settlement, and reputation state
- signed underwriting policy inputs, deterministic underwriting decisions,
  persisted signed decision artifacts, and explicit appeal lifecycle records
- non-mutating underwriting simulation that compares baseline and proposed
  policy outcomes over the same canonical evidence
- signed exposure-ledger and credit-scorecard exports, bounded facility-policy
  evaluation plus signed facility artifacts, deterministic historical credit
  backtests, and one signed provider-facing risk package for external capital
  review
- one bounded bonded-execution simulation lane with explicit operator
  kill-switch and clamp-down semantics over signed bond and loss-lifecycle
  state
- one curated liability-provider registry with fail-closed jurisdiction,
  coverage-class, currency, and evidence-requirement resolution before quote
  or claim state is accepted
- one provider-neutral liability quote, placement, and bound-coverage lane
  over a signed provider-risk package
- immutable liability claim-package, provider-response, dispute, and
  adjudication artifacts linked back to bound coverage, exposure, bond, loss,
  and receipt evidence
- one locally qualified bounded marketplace proof across provider resolution,
  quote-and-bind, and claim/dispute lifecycle evidence
- explicit runtime-assurance tiers that can constrain issuance and later
  governed execution
- one typed SPIFFE-derived workload-identity mapping surface plus one
  canonical multi-cloud appraisal contract, Azure/AWS Nitro/Google verifier
  bridges, explicit trusted-verifier rebinding, fail-closed stale or
  unmatched evidence handling, and one signed appraisal export artifact
- checked-in conformance scenarios plus live JS, Python, and Go peer
  qualification

## Core Evidence Set

- `./scripts/qualify-release.sh`
- `cargo test -p arc-formal-diff-tests`
- `cargo test -p arc-core underwriting -- --nocapture`
- `cargo test -p arc-cli --test receipt_query credit_bonded_execution -- --nocapture`
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
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_metadata_and_review_pack_surfaces -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_arc_oauth_profile_projection -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_missing_sender_binding_material -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_incomplete_runtime_assurance_projection -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_delegated_call_chain_projection -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_check_emits_signed_pass_artifact_and_report -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata -- --exact --nocapture`
- `cargo test -p arc-cli --test certify certify_marketplace_search_transparency_consume_and_dispute_work -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_appeal_and_supersession_lifecycle -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_simulation_report_surfaces -- --exact`
- `cargo test -p arc-core credit -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_credit_backtest_report_surfaces_drift_and_failure_modes -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_provider_risk_package_export_surfaces -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query credit_bonded_execution -- --nocapture`
- `cargo test -p arc-core market -- --nocapture`
- `cargo test -p arc-cli --test receipt_query liability_provider -- --nocapture`
- `cargo test -p arc-cli --test receipt_query liability_market -- --nocapture`
- `cargo test -p arc-cli --test receipt_query liability_claim -- --nocapture`
- `target/release-qualification/conformance/wave1/report.md`
- `target/release-qualification/conformance/wave2/report.md`
- `target/release-qualification/conformance/wave3/report.md`
- `target/release-qualification/conformance/wave4/report.md`
- `target/release-qualification/conformance/wave5/report.md`
- `target/release-qualification/logs/trust-cluster-repeat-run.log`
- [ARC_RECEIPTS_PROFILE.md](../standards/ARC_RECEIPTS_PROFILE.md)
- [ARC_PORTABLE_TRUST_PROFILE.md](../standards/ARC_PORTABLE_TRUST_PROFILE.md)
- [PROTOCOL.md](../../spec/PROTOCOL.md)
- [ECONOMIC_INTEROP_GUIDE.md](../ECONOMIC_INTEROP_GUIDE.md)
- [CREDENTIAL_INTEROP_GUIDE.md](../CREDENTIAL_INTEROP_GUIDE.md)
- [WORKLOAD_IDENTITY_RUNBOOK.md](../WORKLOAD_IDENTITY_RUNBOOK.md)

## Explicit Non-Claims

ARC does not currently claim:

- full theorem-prover coverage for every shipped protocol property
- consensus or multi-region trust replication
- automatic SCIM lifecycle management
- synthetic cross-issuer trust aggregation
- that the behavioral feed itself is the underwriting model rather than a
  truthful evidence input to the separate underwriting surfaces
- that authorization-context exports are independent source-of-truth documents
  rather than derived projections from signed receipts
- generic OID4VP, DIDComm, SD-JWT, or public wallet-network compatibility
  beyond ARC's documented OID4VCI plus narrow verifier-side OID4VP interop
  guide
- attestation-bound sender semantics as standalone authorization outside the
  documented paired DPoP/mTLS confirmation profile
- generic attestation-result interoperability or automatic trust in arbitrary
  cloud attestation providers beyond ARC's documented appraisal contract,
  concrete verifier bridges, and trusted-verifier policy surface
- permissionless or auto-trusting certification marketplace semantics
- automatic claims payment, cross-network recovery clearing, or insurer-network
  messaging beyond ARC's documented liability-market orchestration boundary
- reserve locks, bond execution, liability-market capital allocation, or
  autonomous insurer pricing beyond the documented `v2.20` marketplace
  surface

## Integration Posture

ARC is the rights-and-receipts control plane under MCP, A2A, payment rails,
portable trust, and higher-assurance runtime evidence. It is not positioned as
a replacement transport or a standalone payment network.
