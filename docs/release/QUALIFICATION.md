# Release Qualification

This document defines the production qualification lane for the current ARC
production-candidate surface, including the locally completed `v2.9`
economic-interop additions.

ARC now has two distinct gate types:

- the regular workspace CI lane, which blocks routine regressions quickly
- the release-qualification lane, which proves source-only release inputs,
  dashboard and SDK packaging, conformance-critical behavior, and the repeat-run
  HA control-plane path

## Environments

Regular workspace CI:

- Rust stable with `rustfmt` and `clippy`
- Rust `1.93.0` for the explicit MSRV lane
- `node`
- `python3`
- `go`

Release qualification:

- Rust stable with `rustfmt` and `clippy`
- `node`
- `python3`
- `go`

The dashboard build, TypeScript packaging, Python packaging, Go module
qualification, live JS/Python conformance peers, and repeat-run trust-cluster
proof are mandatory for release qualification. If one runtime is missing, the
lane must fail rather than silently skipping that evidence.

## Commands

Regular workspace lane:

```bash
./scripts/ci-workspace.sh
./scripts/check-sdk-parity.sh
```

Release-qualification lane:

```bash
./scripts/qualify-release.sh
```

Focused release-component lanes:

```bash
./scripts/check-release-inputs.sh
./scripts/check-dashboard-release.sh
./scripts/check-arc-ts-release.sh
./scripts/check-arc-py-release.sh
./scripts/check-arc-go-release.sh
cargo test -p arc-formal-diff-tests
```

The hosted workflow uses
[`.github/workflows/release-qualification.yml`](../../.github/workflows/release-qualification.yml)
and the same `./scripts/qualify-release.sh` entrypoint. The general CI workflow
uses [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

## Qualification Artifacts

The release-qualification script writes conformance evidence under:

- `target/release-qualification/conformance/wave1/`
- `target/release-qualification/conformance/wave2/`
- `target/release-qualification/conformance/wave3/`
- `target/release-qualification/conformance/wave4/`
- `target/release-qualification/conformance/wave5/`

Each wave directory contains:

- `results/` JSON result artifacts
- `report.md` generated Markdown summary

The release-qualification script also records the repeat-run trust-cluster
proof at:

- `target/release-qualification/logs/trust-cluster-repeat-run.log`

The same artifacts can be fed into `ARC Certify` to produce a signed pass/fail
attestation for a selected tool server or release candidate. See
[ARC_CERTIFY_GUIDE.md](../ARC_CERTIFY_GUIDE.md).

The current launch package also consumes the same evidence set through
[RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md),
[RELEASE_AUDIT.md](RELEASE_AUDIT.md), and
[PARTNER_PROOF.md](PARTNER_PROOF.md).

## Evidence Matrix

| Release claim | Primary proving artifact | Qualification command |
| --- | --- | --- |
| Release inputs come from source only and generated artifacts are not tracked | `scripts/check-release-inputs.sh`, root `.gitignore`, package-specific packaging manifests | `./scripts/check-release-inputs.sh` |
| The main Rust workspace is format-clean, lint-clean, and test-clean | workspace crates plus integration/e2e suites | `./scripts/ci-workspace.sh` |
| The dashboard is buildable and testable from a clean install | `crates/arc-cli/dashboard/package.json` and `dist/` output from a temp copy | `./scripts/check-dashboard-release.sh` |
| The TypeScript SDK can be built, packed, and consumed as a package | `packages/sdk/arc-ts/package.json`, packed tarball, and consumer smoke install | `./scripts/check-arc-ts-release.sh` |
| The Python SDK wheel and sdist are reproducible and install cleanly | `packages/sdk/arc-py/pyproject.toml`, built wheel/sdist, and clean venv smoke installs | `./scripts/check-arc-py-release.sh` |
| The Go SDK module qualifies as a module release and consumer dependency | `packages/sdk/arc-go/go.mod`, `go install ./cmd/conformance-peer`, and consumer-module smoke build | `./scripts/check-arc-go-release.sh` |
| Executable scope-attenuation semantics stay aligned with the current shipped runtime surface | `formal/diff-tests/` reference model and differential properties | `cargo test -p arc-formal-diff-tests` |
| HA trust-control remains deterministic on the supported clustered control-plane flow | `crates/arc-cli/tests/trust_cluster.rs` repeat-run qualification plus normal workspace coverage | `cargo test -p arc-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture` |
| The insurer-facing behavioral feed remains signed, filterable, and anchored to canonical trust data | `crates/arc-cli/tests/receipt_query.rs` behavioral-feed endpoint/CLI regression | `cargo test -p arc-cli --test receipt_query test_behavioral_feed_export_surfaces -- --exact` |
| OID4VCI-compatible ARC passport issuance remains replay-safe, fail-closed, remotely usable through public metadata, and now exposes bounded projected `application/dc+sd-jwt` and `jwt_vc_json` passport lanes without widening ARC-native presentation semantics | `crates/arc-credentials/src/oid4vci.rs`, `crates/arc-credentials/src/portable_sd_jwt.rs`, and `crates/arc-credentials/src/portable_jwt_vc.rs` unit coverage plus `crates/arc-cli/tests/passport.rs` local and remote issuance or lifecycle regressions | `cargo test -p arc-credentials oid4vci -- --nocapture && cargo test -p arc-credentials portable_sd_jwt -- --nocapture && cargo test -p arc-credentials portable_jwt_vc_json -- --nocapture && cargo test -p arc-cli --test passport passport_issuance_local_with_published_status_attaches_portable_lifecycle_reference -- --nocapture && cargo test -p arc-cli --test passport passport_issuance_remote_requires_published_status_and_exposes_public_resolution -- --nocapture && cargo test -p arc-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture && cargo test -p arc-cli --test passport passport_portable_jwt_vc_json_metadata_and_issuance_roundtrip -- --nocapture && cargo test -p arc-cli --test passport passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states -- --nocapture && cargo test -p arc-cli --test passport passport_issuance_metadata_rejects_public_status_distribution_without_cache_ttl -- --nocapture && cargo test -p arc-cli --test passport passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution -- --nocapture && cargo test -p arc-cli --test passport passport_portable_metadata_endpoints_require_signing_key_configuration -- --nocapture && cargo test -p arc-cli --test passport passport_issuance_rejects_mixed_portable_profile_request -- --nocapture && cargo test -p arc-cli --test passport passport_issuance_local_portable_offer_requires_signing_seed -- --nocapture && cargo test -p arc-cli --test passport passport_oid4vci -- --nocapture` |
| ARC now ships one narrow verifier-side OID4VP bridge with signed `request_uri` requests, one transport-neutral wallet exchange descriptor and canonical transaction state, one optional verifier-scoped identity assertion continuity lane, same-device and cross-device launch artifacts, verifier metadata, trusted-key `JWKS`, and fail-closed `direct_post.jwt` verification over the projected passport lane | `crates/arc-core/src/session.rs`, `crates/arc-credentials/src/oid4vp.rs` unit coverage plus `crates/arc-cli/tests/passport.rs` verifier transport, wallet-exchange state, identity-assertion continuity, CLI holder adapter, and rotation regressions | `cargo test -p arc-core arc_identity_assertion -- --nocapture && cargo test -p arc-credentials oid4vp -- --nocapture && cargo test -p arc-credentials wallet_exchange_validation_rejects_contradictory_state -- --nocapture && cargo test -p arc-cli --test passport passport_oid4vp_request_uri_and_direct_post_roundtrip_is_replay_safe -- --nocapture && cargo test -p arc-cli --test passport passport_oid4vp_cli_holder_adapter_supports_same_device_and_cross_device_launches -- --nocapture && cargo test -p arc-cli --test passport passport_oid4vp_public_verifier_metadata_and_rotation_preserve_active_request_truth -- --nocapture` |
| ARC's hosted authorization edge now preserves bounded sender-constrained semantics across authorization-code exchange, token issuance, and protected-resource admission over DPoP, mTLS thumbprint binding, and one attestation-bound confirmation profile without widening authority from attestation alone | `crates/arc-cli/src/remote_mcp.rs` sender-constrained runtime enforcement, `crates/arc-kernel/src/operator_report.rs` discovery metadata proof-type publication, and `crates/arc-cli/tests/mcp_auth_server.rs` sender-proof regressions | `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime -- --exact --nocapture --test-threads=1 && cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint -- --exact --nocapture --test-threads=1 && cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls -- --exact --nocapture --test-threads=1` |
| ARC passport presentation now supports one bounded holder-facing transport over public challenge fetch and public response submit routes without widening verifier admin authority | `crates/arc-cli/tests/passport.rs` public holder transport regression plus the existing replay-safe verifier challenge store | `cargo test -p arc-cli --test passport passport_public_holder_transport_fetch_submit_and_fail_closed_on_replay -- --nocapture && cargo test -p arc-cli --test passport passport_policy_reference_flow_is_replay_safe_locally -- --nocapture` |
| ARC proves one external raw-HTTP portable credential interop lane end-to-end without relying on ARC CLI wrappers on the remote side, and one CLI holder adapter lane over the supported verifier bridge | `crates/arc-cli/tests/passport.rs` raw-HTTP issuance plus verifier-transport regressions and the focused interop guide | `cargo test -p arc-cli --test passport passport_external_http_issuance_and_verifier_roundtrip_is_interop_qualified -- --nocapture && cargo test -p arc-cli --test passport passport_oid4vp_cli_holder_adapter_supports_same_device_and_cross_device_launches -- --nocapture` |
| The underwriting policy-input snapshot remains signed, anchored to canonical trust data, and fail-closed on unscoped queries | `crates/arc-cli/tests/receipt_query.rs` underwriting-input endpoint/CLI regression | `cargo test -p arc-cli --test receipt_query test_underwriting_policy_input_export_surfaces -- --exact` |
| The underwriting decision and issuance surfaces remain deterministic, evidence-linked, and fail-closed on missing scope, missing history, or invalid issue requests | `crates/arc-core/src/underwriting.rs` evaluator unit coverage plus `crates/arc-cli/tests/receipt_query.rs` underwriting endpoint/CLI regressions | `cargo test -p arc-core underwriting -- --nocapture && cargo test -p arc-cli --test receipt_query test_underwriting_decision_report_surfaces -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_decision_steps_up_without_receipt_history -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_decision_requires_anchor -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_requires_anchor -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_decision_links_failed_settlement_evidence -- --exact` |
| Signed underwriting decisions, supersession, and appeals remain queryable without mutating prior signed artifacts or canonical receipts, while currency and appeal lifecycle invariants stay explicit | `crates/arc-core/src/underwriting.rs` artifact signing coverage plus `crates/arc-cli/tests/receipt_query.rs` decision issue/list and appeal lifecycle regressions | `cargo test -p arc-core underwriting -- --nocapture && cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_appeal_and_supersession_lifecycle -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_rejected_appeal_cannot_link_replacement_decision -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_with_mixed_currency_exposure_withholds_premium -- --exact && cargo test -p arc-cli --test receipt_query test_underwriting_decision_list_partitions_premium_totals_by_currency -- --exact` |
| Underwriting simulation remains non-mutating while surfacing baseline-versus-simulated outcome deltas over the same canonical evidence | `crates/arc-cli/tests/receipt_query.rs` underwriting-simulation endpoint/CLI regression | `cargo test -p arc-cli --test receipt_query test_underwriting_simulation_report_surfaces -- --exact` |
| The signed exposure ledger remains anchored to canonical receipt and underwriting truth, partitions economic position by currency, and fails closed on unscoped or contradictory row state | `crates/arc-core/src/credit.rs` unit coverage plus `crates/arc-cli/tests/receipt_query.rs` exposure-ledger endpoint/CLI regressions | `cargo test -p arc-core --lib credit -- --nocapture && cargo test -p arc-cli --test receipt_query exposure_ledger -- --nocapture` |
| The signed credit scorecard remains subject-scoped, probation-aware, anomaly-linked, and fail-closed on missing subject scope or missing exposure history | `crates/arc-cli/tests/receipt_query.rs` credit-scorecard endpoint/CLI regressions | `cargo test -p arc-cli --test receipt_query credit_scorecard -- --nocapture` |
| Facility-policy evaluation and signed facility issuance remain bounded, prerequisite-aware, and explicit about grant/manual-review/deny posture without cross-currency auto-allocation | `crates/arc-cli/tests/receipt_query.rs` facility-policy endpoint/CLI regressions | `cargo test -p arc-cli --test receipt_query credit_facility -- --nocapture` |
| Credit backtests and the signed provider-risk package remain deterministic, recent-loss-aware, and honest enough for external capital review without implying bond execution or liability-market clearing | `crates/arc-core/src/credit.rs` signing coverage plus `crates/arc-cli/tests/receipt_query.rs` backtest and provider-package regressions | `cargo test -p arc-core credit -- --nocapture && cargo test -p arc-cli --test receipt_query test_credit_backtest_report_surfaces_drift_and_failure_modes -- --exact --nocapture && cargo test -p arc-cli --test receipt_query test_provider_risk_package_export_surfaces -- --exact --nocapture` |
| Bond-policy evaluation and signed bond issuance now expose reserve `lock`/`hold`/`release`/`impair` posture, preserve collateral provenance to the latest active facility, and fail closed on mixed-currency reserve accounting | `crates/arc-core/src/credit.rs` bond-query/signing coverage plus `crates/arc-cli/tests/receipt_query.rs` bond-policy endpoint, issuance, list, and fail-closed regressions | `cargo test -p arc-core credit -- --nocapture && cargo test -p arc-cli --test receipt_query test_credit_bond -- --nocapture` |
| Delegated and autonomous governed execution now fail closed unless explicit autonomy context, sufficient runtime assurance, valid call-chain binding, and one active delegation bond all still satisfy runtime reserve posture | `crates/arc-core/src/capability.rs` autonomy contracts, `crates/arc-kernel/src/lib.rs` governed runtime enforcement, concrete receipt-store bond lookup, and `crates/arc-cli/tests/receipt_query.rs` bond-report regressions | `cargo test -p arc-core constraint_serde_roundtrip -- --nocapture && cargo test -p arc-core governed_transaction_receipt_metadata_serde_roundtrip -- --nocapture && cargo test -p arc-kernel autonomy -- --nocapture && cargo test -p arc-kernel weak_runtime_assurance -- --nocapture && cargo test -p arc-cli --test receipt_query test_credit_bond -- --nocapture` |
| Bond-loss lifecycle evaluation and issuance now keep delinquency, recovery, reserve-release, and write-off state immutable, evidence-linked, and fail closed on premature release or over-booked recovery | `crates/arc-cli/src/trust_control.rs` loss-lifecycle accounting and issuance surfaces, `crates/arc-store-sqlite/src/receipt_store.rs` immutable lifecycle persistence, and `crates/arc-cli/tests/receipt_query.rs` loss-lifecycle endpoint and list regressions | `cargo test -p arc-cli --test receipt_query credit_loss_lifecycle -- --nocapture && cargo test -p arc-cli --test receipt_query test_credit_bond_report_impairs_and_fails_closed_on_mixed_currency -- --nocapture` |
| Bonded execution now has one operator-visible simulation and sandbox qualification lane with explicit kill-switch and clamp-down semantics over signed bond and loss-lifecycle truth | `crates/arc-core/src/credit.rs` bonded-execution simulation contract, `crates/arc-cli/src/trust_control.rs` simulation endpoint and evaluator, `crates/arc-cli/src/main.rs` `trust bond simulate`, and `crates/arc-cli/tests/receipt_query.rs` end-to-end simulation regression | `cargo test -p arc-core credit -- --nocapture && cargo test -p arc-cli --test receipt_query credit_bonded_execution -- --nocapture` |
| The liability-provider registry remains curated, supersession-aware, jurisdiction-bounded, and fail closed on unsupported provider, coverage-class, or currency resolution | `crates/arc-core/src/market.rs` liability-provider contract and validation coverage, `crates/arc-store-sqlite/src/receipt_store.rs` durable provider publication and resolution logic, `crates/arc-cli/src/trust_control.rs` provider issue/list/resolve surfaces, and `crates/arc-cli/tests/receipt_query.rs` provider-registry endpoint and CLI regressions | `cargo test -p arc-core market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_provider -- --nocapture` |
| Liability-market quote, placement, and bound-coverage workflows remain provider-neutral, durable, and fail closed on stale provider records, expired quotes, placement mismatches, or unsupported bound-coverage policy | `crates/arc-core/src/market.rs` quote-and-bind contract and validation coverage, `crates/arc-store-sqlite/src/receipt_store.rs` workflow persistence and reporting, `crates/arc-cli/src/trust_control.rs` trust-control plus CLI issuance surfaces, and `crates/arc-cli/tests/receipt_query.rs` liability-market regressions | `cargo test -p arc-core market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_market -- --nocapture` |
| Liability-market claim, dispute, and adjudication workflows remain immutable, evidence-linked, and fail closed on oversized claims or invalid dispute state | `crates/arc-core/src/market.rs` claim and adjudication contracts, `crates/arc-store-sqlite/src/receipt_store.rs` immutable claim workflow persistence, `crates/arc-cli/src/trust_control.rs` claim issuance plus reporting surfaces, `crates/arc-cli/src/main.rs` liability-market CLI issuance and list commands, and `crates/arc-cli/tests/receipt_query.rs` end-to-end claim workflow regressions | `cargo test -p arc-core market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_claim -- --nocapture` |
| ARC's bounded liability-market posture is qualified end to end across curated provider resolution, quote and bind, and claim or dispute workflow evidence without implying automatic claims payment or autonomous insurer pricing | the provider-registry, quote-and-bind, and claim-workflow regressions together with the updated partner-proof and release-boundary docs | `cargo test -p arc-core market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_provider -- --nocapture && cargo test -p arc-cli --test receipt_query liability_market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_claim -- --nocapture` |
| Metered billing evidence remains separate from signed receipt truth while staying operator-reconcilable | `crates/arc-cli/tests/receipt_query.rs` metered-billing reconciliation regression | `cargo test -p arc-cli --test receipt_query test_metered_billing_reconciliation_report_and_action_endpoint -- --exact` |
| Governed receipts can be projected into enterprise-facing authorization-context, metadata, and reviewer-pack reports without widening scope, and the hosted request-time authorization flow now preserves the same bounded ARC profile across `authorization_details`, `arc_transaction_context`, protected-resource `resource` binding, optional identity-assertion continuity, and runtime-versus-audit artifact boundaries | `crates/arc-cli/tests/receipt_query.rs` authorization-context endpoint, metadata, reviewer-pack, and negative-path regressions plus hosted discovery and request-time authorization regressions in `crates/arc-cli/tests/mcp_auth_server.rs` | `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_metadata_and_review_pack_surfaces -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_arc_oauth_profile_projection -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_missing_sender_binding_material -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_incomplete_runtime_assurance_projection -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_delegated_call_chain_projection -- --exact && cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer -- --exact --nocapture && cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture && cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_stale_or_mismatched_identity_assertion -- --exact --nocapture` |
| ARC Certify public marketplace surfaces remain evidence-backed and fail closed: certification artifacts advertise one versioned evidence profile, public discovery metadata rejects stale or mismatched publishers, search and transparency preserve operator provenance, and consume plus dispute flows never auto-grant trust from listing visibility | `crates/arc-cli/tests/certify.rs` public metadata, marketplace search/transparency, consume, and dispute regressions | `cargo test -p arc-cli --test certify certify_check_emits_signed_pass_artifact_and_report -- --exact --nocapture && cargo test -p arc-cli --test certify certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata -- --exact --nocapture && cargo test -p arc-cli --test certify certify_marketplace_search_transparency_consume_and_dispute_work -- --exact --nocapture` |
| SPIFFE/SVID-style workload identity maps into runtime attestation, policy, issuance, and governed receipts without silently widening opaque verifier identity | `crates/arc-core/src/capability.rs` parsing/binding unit coverage, `crates/arc-policy/src/evaluate/tests.rs` workload-identity policy regressions, `crates/arc-cli/src/issuance.rs` issuance fail-closed regression compiled through `arc-control-plane`, and `crates/arc-kernel/src/lib.rs` governed runtime/receipt regressions | `cargo test -p arc-core workload_identity -- --nocapture && cargo test -p arc-policy tool_access_workload_identity -- --nocapture && cargo test -p arc-control-plane workload_identity_validation_denies_conflicting_attestation_without_policy -- --nocapture && cargo test -p arc-kernel governed_request_denies_conflicting_workload_identity_binding -- --nocapture && cargo test -p arc-kernel governed_monetary_allow_records_runtime_assurance_metadata -- --nocapture` |
| Azure Attestation JWTs, AWS Nitro attestation documents, and Google Confidential VM JWTs normalize into one canonical ARC appraisal boundary without silently widening unsupported evidence above `attested` | `crates/arc-core/src/appraisal.rs` canonical appraisal coverage plus `crates/arc-control-plane/src/attestation.rs` Azure, Nitro, and Google verifier coverage over issuer trust, certificate or `JWKS` validation, freshness, measurements, secure-boot posture, and optional workload-identity projection | `cargo test -p arc-core appraisal -- --nocapture && cargo test -p arc-control-plane azure_maa -- --nocapture && cargo test -p arc-control-plane aws_nitro -- --nocapture && cargo test -p arc-control-plane google_confidential_vm -- --nocapture` |
| Explicit attestation trust policy can rebind trusted Azure, AWS Nitro, and Google verifier evidence into stronger runtime-assurance tiers while rejecting stale or unmatched verifier evidence fail closed | `crates/arc-core/src/capability.rs` trust-policy resolver coverage, `crates/arc-policy/src/validate.rs` trusted-verifier validation, `crates/arc-control-plane/src/attestation.rs` policy-bound verifier tests, `crates/arc-kernel/src/lib.rs` governed-runtime trust-policy regressions, and [WORKLOAD_IDENTITY_RUNBOOK.md](../WORKLOAD_IDENTITY_RUNBOOK.md) | `cargo test -p arc-core runtime_attestation_trust_policy -- --nocapture && cargo test -p arc-policy runtime_assurance_validation -- --nocapture && cargo test -p arc-control-plane runtime_assurance_policy -- --nocapture && cargo test -p arc-kernel governed_request_denies_untrusted_attestation_when_trust_policy_is_configured -- --nocapture && cargo test -p arc-kernel governed_monetary_allow_rebinds_trusted_attestation_to_verified -- --nocapture && cargo test -p arc-kernel governed_monetary_allow_rebinds_google_attestation_to_verified -- --nocapture` |
| Operators can export one signed runtime-attestation appraisal report that captures verifier family, evidence descriptor, normalized assertions, vendor-scoped claims, and policy-visible outcome without claiming generic attestation-result interoperability | `crates/arc-cli/src/trust_control.rs` appraisal export surface, `crates/arc-cli/src/main.rs` CLI export path, `crates/arc-cli/tests/receipt_query.rs` remote plus local export regression, and [WORKLOAD_IDENTITY_RUNBOOK.md](../WORKLOAD_IDENTITY_RUNBOOK.md) | `cargo test -p arc-cli --test receipt_query test_runtime_attestation_appraisal_export_surfaces -- --exact --nocapture` |
| Wrapped/runtime MCP compatibility remains truthful across live peer waves | live conformance results under `target/release-qualification/conformance/` | `./scripts/qualify-release.sh` |

Lean proof artifacts are informative, but they are not a release gate until the
root-imported proof surface is aligned with the shipped runtime and free of
`sorry`.

## Release Rule

Do not tag or announce a production candidate from a green workspace run alone.

Release readiness for the current surface requires:

1. `./scripts/ci-workspace.sh` green
2. `./scripts/check-sdk-parity.sh` green
3. `./scripts/qualify-release.sh` green
4. the explicit MSRV lane in `.github/workflows/ci.yml` green on Rust `1.93.0`
5. [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md),
   [RELEASE_AUDIT.md](RELEASE_AUDIT.md), and
   [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) updated together
6. [OBSERVABILITY.md](OBSERVABILITY.md),
   [GA_CHECKLIST.md](GA_CHECKLIST.md), and
   [RISK_REGISTER.md](RISK_REGISTER.md) updated together

If a hosted CI run cannot be observed from the current environment, record that
as an explicit procedural note in the release audit instead of implying it
happened.
