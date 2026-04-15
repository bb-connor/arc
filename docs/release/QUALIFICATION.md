# Release Qualification

This document defines the qualification lane for the current bounded ARC
release candidate. The ship boundary is intentionally narrower than the
stronger repo-local v3.16 and v3.17 thesis gates: bounded ARC is the
release-facing claim, while stronger technical-control-plane and
comptroller-capable packaging claims remain optional addenda.

Use the release documents this way:

- [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md) defines the supported
  candidate surface
- this document defines the evidence and command contract for that surface
- [RELEASE_AUDIT.md](RELEASE_AUDIT.md) is the authoritative repo-local
  release-go or hold record
- [GA_CHECKLIST.md](GA_CHECKLIST.md) is the operator-facing publication
  checklist
- [PARTNER_PROOF.md](PARTNER_PROOF.md) and
  [ARC_WEB3_PARTNER_PROOF.md](ARC_WEB3_PARTNER_PROOF.md) are reviewer-facing
  packages derived from the same evidence lanes

ARC now has four distinct gate types:

- the regular workspace CI lane, which blocks routine regressions quickly
- the bounded ARC release gate, which proves the current ship-facing boundary
  and records the supported local-only, leader-local, informational-only, and
  compatibility-only surfaces explicitly
- the release-qualification lane, which proves source-only release inputs,
  dashboard and SDK packaging, conformance-critical behavior, and the bounded
  operational profile
- the focused claim-gate lanes, which qualify increasingly strong technical and
  market-adjacent statements without pretending repo-local evidence proves the
  broader market thesis

## Bounded ARC Release Gate

For the current ship decision, ARC has one primary release gate:

- `./scripts/qualify-bounded-arc.sh`

This command is the authoritative bounded ARC ship gate. It records:

- the named bounded operational profile used for release
- the exact guarantee class for the sensitive surfaces that were previously
  overclaimed
- the retained non-claims: no consensus-grade HA, no distributed-linearizable
  budget authority, no public transparency-log semantics, no authenticated
  recursive delegation ancestry beyond the preserved chain, and no proved
  market-position thesis

The strongest honest ship-facing claim ARC can now make is:

- ARC ships a cryptographically signed, fail-closed governance and evidence
  control plane with bounded delegated-authority semantics, bounded hosted/auth
  profiles, bounded provenance semantics, signed receipts and checkpoints, and
  explicit local or leader-local operational contracts for trust-control,
  budgets, and review surfaces.

That bounded release does **not** qualify:

- theorem-prover completion for every protocol claim
- authenticated recursive delegation ancestry beyond the preserved
  caller-presented chain
- verifier-backed runtime assurance as the sole admission boundary
- consensus-grade HA or distributed-linearizable budget truth
- public transparency-log or strong non-repudiation semantics
- a proved "comptroller of the agent economy" market position

The machine-readable gate for this lane is:

- [ARC_BOUNDED_ARC_QUALIFICATION_MATRIX.json](../standards/ARC_BOUNDED_ARC_QUALIFICATION_MATRIX.json)

Its artifact bundle is written to:

- `target/release-qualification/bounded-arc/`

## Additional Claim-Gate Addenda

ARC also retains three stronger repo-local claim gates for technical and
strategic review work:

- `./scripts/qualify-cross-protocol-runtime.sh`
- `./scripts/qualify-universal-control-plane.sh`
- `./scripts/qualify-comptroller-market-position.sh`

Those commands are additive and are not the front-door bounded release
requirement. They remain useful when a reviewer wants the stronger local
technical-control-plane or comptroller-capable packaging evidence.

- `./scripts/qualify-cross-protocol-runtime.sh` qualifies the bounded
  cross-protocol runtime substrate and representative SDK/runtime surface
- `./scripts/qualify-universal-control-plane.sh` qualifies the stronger
  technical control-plane thesis on top of that substrate
- `./scripts/qualify-comptroller-market-position.sh` qualifies the strongest
  honest repo-local economic/control-plane boundary: comptroller-capable
  software with qualified operator, partner, and bounded federated proof,
  while still refusing the stronger proved-market-position claim

The machine-readable gates for the stronger addenda are:

- [ARC_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json](../standards/ARC_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json)
- [ARC_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json](../standards/ARC_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json)
- [ARC_COMPTROLLER_MARKET_POSITION_MATRIX.json](../standards/ARC_COMPTROLLER_MARKET_POSITION_MATRIX.json)

Their artifact bundles are written to:

- `target/release-qualification/cross-protocol-runtime/`
- `target/release-qualification/universal-control-plane/`
- `target/release-qualification/comptroller-market-position/`

The current retained decision is therefore:

- ship bounded ARC on the bounded release gate above
- keep the stronger cross-protocol, universal-control-plane, and
  comptroller-capable gates as separate optional addenda
- do not treat those stronger addenda as the primary shipping boundary
- do not upgrade the broader market-position thesis

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
./scripts/qualify-bounded-arc.sh
./scripts/qualify-release.sh
```

Focused stronger claim-gates:

```bash
./scripts/qualify-cross-protocol-runtime.sh
./scripts/qualify-universal-control-plane.sh
./scripts/qualify-comptroller-market-position.sh
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

Targeted endgame market-discipline lanes currently used in local qualification:

```bash
CARGO_INCREMENTAL=0 cargo test -p arc-core open_market -- --nocapture
CARGO_INCREMENTAL=0 cargo test -p arc-core --lib \
  generic_listing_search_rejects_reports_with_invalid_listing_signatures \
  -- --nocapture
CARGO_INCREMENTAL=0 cargo test -p arc-core --lib \
  non_local_activation_authority -- --nocapture
CARGO_INCREMENTAL=0 cargo test -p arc-cli --test certify \
  certify_open_market_fee_schedules_and_slashing_require_explicit_bounded_authority \
  -- --exact --nocapture
CARGO_INCREMENTAL=0 cargo test -p arc-cli --test certify \
  certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust \
  -- --exact --nocapture
```

Targeted web3-runtime qualification lanes currently used in local milestone
closure:

```bash
./scripts/qualify-web3-runtime.sh
./scripts/qualify-web3-e2e.sh
./scripts/qualify-web3-ops-controls.sh
CARGO_TARGET_DIR=target/arc-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p arc-anchor -- --test-threads=1
CARGO_TARGET_DIR=target/arc-link-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p arc-link -- --test-threads=1
CARGO_TARGET_DIR=target/arc-kernel-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p arc-kernel cross_currency -- --test-threads=1
CARGO_TARGET_DIR=target/arc-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p arc-settle --lib -- --test-threads=1
CARGO_TARGET_DIR=target/arc-settle-runtime CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p arc-settle --test runtime_devnet -- --nocapture
pnpm --dir contracts devnet:smoke
for f in \
  docs/standards/ARC_LINK_BASE_MAINNET_CONFIG.json \
  docs/standards/ARC_LINK_MONITOR_REPORT_EXAMPLE.json \
  docs/standards/ARC_LINK_QUALIFICATION_MATRIX.json \
  docs/standards/ARC_ANCHOR_RUNTIME_REPORT_EXAMPLE.json \
  docs/standards/ARC_FUNCTIONS_REQUEST_EXAMPLE.json \
  docs/standards/ARC_FUNCTIONS_RESPONSE_EXAMPLE.json \
  docs/standards/ARC_ANCHOR_AUTOMATION_JOB_EXAMPLE.json \
  docs/standards/ARC_SETTLEMENT_WATCHDOG_JOB_EXAMPLE.json \
  docs/standards/ARC_CCIP_MESSAGE_EXAMPLE.json \
  docs/standards/ARC_CCIP_RECONCILIATION_EXAMPLE.json \
  docs/standards/ARC_X402_REQUIREMENTS_EXAMPLE.json \
  docs/standards/ARC_EIP3009_TRANSFER_WITH_AUTHORIZATION_EXAMPLE.json \
  docs/standards/ARC_CIRCLE_NANOPAYMENT_EXAMPLE.json \
  docs/standards/ARC_4337_PAYMASTER_COMPAT_EXAMPLE.json \
  docs/standards/ARC_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json \
  docs/standards/ARC_SETTLE_FINALITY_REPORT_EXAMPLE.json \
  docs/standards/ARC_SETTLE_RUNTIME_REPORT_EXAMPLE.json \
  docs/standards/ARC_SETTLE_SOLANA_RELEASE_EXAMPLE.json \
  docs/standards/ARC_SETTLE_QUALIFICATION_MATRIX.json \
  docs/standards/ARC_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json \
  docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json \
  docs/standards/ARC_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json; do
  jq empty "$f"
done
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
| Clustered trust-control remains a bounded leader-local control-plane flow rather than a consensus system | `crates/arc-cli/tests/trust_cluster.rs` repeat-run qualification plus normal workspace coverage | `cargo test -p arc-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture` |
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
| The signed capital book remains anchored to canonical receipt, facility, bond, and loss-lifecycle truth, attributes one live source-of-funds story conservatively, and fails closed on missing subject scope, mixed currency, missing counterparty attribution, or ambiguous live capital sources | `crates/arc-core/src/credit.rs`, `crates/arc-cli/src/trust_control.rs`, `crates/arc-store-sqlite/src/receipt_store.rs`, and `crates/arc-cli/tests/receipt_query.rs` capital-book regressions | `cargo test -p arc-core capital_book -- --nocapture && cargo test -p arc-cli --test receipt_query capital_book -- --nocapture` |
| The signed capital-instruction artifact remains custody-neutral, authority-scoped, and fail closed on stale approval chains, mismatched custody steps, contradictory execution windows, overstated source amounts, or observed execution that does not match the intended movement | `crates/arc-core/src/credit.rs` instruction-signing coverage plus `crates/arc-cli/src/trust_control.rs`, `crates/arc-cli/src/main.rs`, and `crates/arc-cli/tests/receipt_query.rs` capital-instruction endpoint, CLI, and negative-path regressions | `cargo test -p arc-core capital_execution_instruction -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query capital_instruction -- --nocapture` |
| The signed capital-allocation artifact remains governed-receipt-bound, simulation-first, and fail closed on ambiguous receipt selection, missing reserve backing, stale authority, or utilization and concentration boundary hits | `crates/arc-core/src/credit.rs` allocation-signing coverage plus `crates/arc-cli/src/trust_control.rs`, `crates/arc-cli/src/main.rs`, and `crates/arc-cli/tests/receipt_query.rs` capital-allocation endpoint, CLI, and boundary regressions | `cargo test -p arc-core capital_allocation_decision -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_capital_allocation -- --nocapture` |
| ARC's live-capital claim remains explicit and bounded: capital-book, instruction, and allocation surfaces are qualified together, while regulated-role assumptions stay documented and ARC does not imply that it is the regulated custodian, settlement rail, or insurer of record | the combined capital-book, capital-instruction, and capital-allocation regressions together with the updated protocol, release, and partner-boundary docs | `cargo test -p arc-core capital_book -- --nocapture && cargo test -p arc-core capital_execution_instruction -- --nocapture && cargo test -p arc-core capital_allocation_decision -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query capital_book -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query capital_instruction -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_capital_allocation -- --nocapture` |
| Bond-policy evaluation and signed bond issuance now expose reserve `lock`/`hold`/`release`/`impair` posture, preserve collateral provenance to the latest active facility, and fail closed on mixed-currency reserve accounting | `crates/arc-core/src/credit.rs` bond-query/signing coverage plus `crates/arc-cli/tests/receipt_query.rs` bond-policy endpoint, issuance, list, and fail-closed regressions | `cargo test -p arc-core credit -- --nocapture && cargo test -p arc-cli --test receipt_query test_credit_bond -- --nocapture` |
| Delegated and autonomous governed execution now fail closed unless explicit autonomy context, sufficient runtime assurance, valid call-chain binding, and one active delegation bond all still satisfy runtime reserve posture | `crates/arc-core/src/capability.rs` autonomy contracts, `crates/arc-kernel/src/lib.rs` governed runtime enforcement, concrete receipt-store bond lookup, and `crates/arc-cli/tests/receipt_query.rs` bond-report regressions | `cargo test -p arc-core constraint_serde_roundtrip -- --nocapture && cargo test -p arc-core governed_transaction_receipt_metadata_serde_roundtrip -- --nocapture && cargo test -p arc-kernel autonomy -- --nocapture && cargo test -p arc-kernel weak_runtime_assurance -- --nocapture && cargo test -p arc-cli --test receipt_query test_credit_bond -- --nocapture` |
| Bond-loss lifecycle evaluation and issuance now keep delinquency, recovery, reserve-release, reserve-slash, and write-off state immutable, evidence-linked, and fail closed on premature release, missing reserve-control execution metadata, stale authority, over-booked recovery, or contradictory reserve movement | `crates/arc-cli/src/trust_control.rs` loss-lifecycle accounting and reserve-control issuance surfaces, `crates/arc-store-sqlite/src/receipt_store.rs` immutable lifecycle persistence, `crates/arc-cli/src/main.rs` reserve-control CLI request loading, and `crates/arc-cli/tests/receipt_query.rs` loss-lifecycle endpoint and list regressions | `cargo test -p arc-cli --test receipt_query credit_loss_lifecycle -- --nocapture && cargo test -p arc-cli --test receipt_query test_credit_bond_report_impairs_and_fails_closed_on_mixed_currency -- --nocapture` |
| Bonded execution now has one operator-visible simulation and sandbox qualification lane with explicit kill-switch and clamp-down semantics over signed bond and loss-lifecycle truth | `crates/arc-core/src/credit.rs` bonded-execution simulation contract, `crates/arc-cli/src/trust_control.rs` simulation endpoint and evaluator, `crates/arc-cli/src/main.rs` `trust bond simulate`, and `crates/arc-cli/tests/receipt_query.rs` end-to-end simulation regression | `cargo test -p arc-core credit -- --nocapture && cargo test -p arc-cli --test receipt_query credit_bonded_execution -- --nocapture` |
| The liability-provider registry remains curated, supersession-aware, jurisdiction-bounded, and fail closed on unsupported provider, coverage-class, or currency resolution | `crates/arc-core/src/market.rs` liability-provider contract and validation coverage, `crates/arc-store-sqlite/src/receipt_store.rs` durable provider publication and resolution logic, `crates/arc-cli/src/trust_control.rs` provider issue/list/resolve surfaces, and `crates/arc-cli/tests/receipt_query.rs` provider-registry endpoint and CLI regressions | `cargo test -p arc-core market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_provider -- --nocapture` |
| Liability-market delegated pricing-authority, quote, placement, and bound-coverage workflows remain provider-bounded, capital-linked, and fail closed on stale provider records, stale authority, expired quotes, placement mismatches, or out-of-envelope coverage and premium requests | `crates/arc-core/src/market.rs` pricing-authority, auto-bind, quote, and bind contract coverage, `crates/arc-store-sqlite/src/receipt_store.rs` workflow persistence and reporting, `crates/arc-cli/src/trust_control.rs` trust-control plus CLI issuance surfaces, and `crates/arc-cli/tests/receipt_query.rs` liability-market regressions | `cargo test -p arc-core market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_market -- --nocapture --test-threads=1` |
| Liability-market claim, dispute, adjudication, payout, and settlement workflows remain immutable, evidence-linked, and fail closed on oversized claims, invalid dispute state, duplicate payout receipts, stale settlement authority, or mismatched settlement topology | `crates/arc-core/src/market.rs` claim, payout, and settlement contracts, `crates/arc-store-sqlite/src/receipt_store.rs` immutable claim-workflow persistence, `crates/arc-cli/src/trust_control.rs` claim, payout, and settlement issuance surfaces, `crates/arc-cli/src/main.rs` liability-market CLI issuance and list commands, and `crates/arc-cli/tests/receipt_query.rs` end-to-end workflow regressions | `cargo test -p arc-core market -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_liability_claim_workflow_surfaces -- --exact --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_liability_claim_rejects_oversized_claims_and_invalid_disputes -- --exact --nocapture` |
| ARC's bounded liability-market posture is qualified end to end across curated provider resolution, delegated pricing authority, quote and bind, claim workflow evidence, and one explicit payout-and-settlement lane without implying autonomous insurer pricing beyond the delegated envelope or open-ended cross-organization recovery clearing | the provider-registry, delegated-pricing/quote-and-bind, claim-workflow, and settlement-workflow regressions together with the updated partner-proof and release-boundary docs | `cargo test -p arc-core market -- --nocapture && cargo test -p arc-cli --test receipt_query liability_provider -- --nocapture && cargo test -p arc-cli --test receipt_query liability_market -- --nocapture --test-threads=1 && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_liability_claim_workflow_surfaces -- --exact --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_liability_claim_rejects_oversized_claims_and_invalid_disputes -- --exact --nocapture` |
| Metered billing evidence remains separate from signed receipt truth while staying operator-reconcilable | `crates/arc-cli/tests/receipt_query.rs` metered-billing reconciliation regression | `cargo test -p arc-cli --test receipt_query test_metered_billing_reconciliation_report_and_action_endpoint -- --exact` |
| Governed receipts can be projected into enterprise-facing authorization-context, metadata, and reviewer-pack reports without widening scope, while delegated call-chain context remains preserved caller context unless separately verified and the hosted request-time authorization flow keeps the same bounded ARC profile across `authorization_details`, `arc_transaction_context`, protected-resource `resource` binding, optional identity-assertion continuity, and runtime-versus-audit artifact boundaries | `crates/arc-cli/tests/receipt_query.rs` authorization-context endpoint, metadata, reviewer-pack, and negative-path regressions plus hosted discovery and request-time authorization regressions in `crates/arc-cli/tests/mcp_auth_server.rs` | `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_metadata_and_review_pack_surfaces -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_arc_oauth_profile_projection -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_missing_sender_binding_material -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_incomplete_runtime_assurance_projection -- --exact && cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_delegated_call_chain_projection -- --exact && cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer -- --exact --nocapture && cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture && cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_stale_or_mismatched_identity_assertion -- --exact --nocapture` |
| ARC Certify public marketplace surfaces remain evidence-backed and fail closed: certification artifacts advertise one versioned evidence profile, public discovery metadata rejects stale or mismatched publishers, and search plus transparency remain signed visibility feeds that preserve operator provenance without auto-granting trust from listing visibility | `crates/arc-cli/tests/certify.rs` public metadata, marketplace search/transparency, consume, and dispute regressions | `cargo test -p arc-cli --test certify certify_check_emits_signed_pass_artifact_and_report -- --exact --nocapture && cargo test -p arc-cli --test certify certify_registry_discover_fails_closed_on_stale_and_mismatched_public_metadata -- --exact --nocapture && cargo test -p arc-cli --test certify certify_marketplace_search_transparency_consume_and_dispute_work -- --exact --nocapture` |
| The bounded generic registry substrate keeps namespace ownership explicit and auditable, projects current tool-server, issuer, verifier, and liability-provider surfaces through one signed listing envelope, makes origin/mirror/indexer publisher roles plus deterministic search-policy and freshness metadata explicit, and fails closed on contradictory ownership or stale/divergent replica state without turning visibility into trust admission | `crates/arc-core/src/listing.rs` generic namespace/listing/aggregation contract, `crates/arc-cli/src/trust_control.rs` public namespace plus listing projection surfaces, and `crates/arc-cli/tests/certify.rs` generic-registry regression | `CARGO_INCREMENTAL=0 cargo test -p arc-core generic_listing_ -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test certify certify_public_generic_registry_namespace_and_listings_project_current_actor_families -- --exact --nocapture` |
| Open-registry trust activation remains explicit, local, machine-readable, and fail closed: one signed local activation artifact binds one listing plus review context and eligibility policy, `public_untrusted` never admits, `reviewable` admits only after approval, and stale or incompatible registry state rejects runtime trust import | `crates/arc-core/src/listing.rs` trust-activation contract and `crates/arc-cli/tests/certify.rs` local activation issue/evaluate regression | `CARGO_INCREMENTAL=0 cargo test -p arc-core --lib generic_trust_activation_ -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test certify certify_generic_registry_trust_activation_requires_explicit_local_activation_and_fails_closed -- --exact --nocapture` |
| Open-registry governance remains signed, scope-bounded, and fail closed: governance charters declare namespace and operator authority plus allowed case kinds, dispute/freeze/sanction/appeal cases bind to listing and optional activation truth, and expired, unauthorized, invalid-appeal, or unsupported governance actions reject rather than widening trust | `crates/arc-core/src/governance.rs` governance contract, `crates/arc-cli/src/trust_control.rs` charter/case issue and evaluate surfaces, and `crates/arc-cli/tests/certify.rs` governance regression | `CARGO_INCREMENTAL=0 cargo test -p arc-core --lib generic_governance_ -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test certify certify_generic_registry_governance_charters_and_cases_enforce_bounded_open_governance -- --exact --nocapture` |
| Portable reputation exchange remains signed, provenance-preserving, locally weighted, and fail closed on stale, duplicate, contradictory, or disallowed issuer inputs instead of becoming a global trust score | `crates/arc-credentials/src/portable_reputation.rs`, `crates/arc-cli/src/trust_control.rs`, and `crates/arc-cli/tests/local_reputation.rs` | `CARGO_INCREMENTAL=0 cargo test -p arc-credentials portable_reputation -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test local_reputation trust_service_portable_reputation_issue_and_evaluate_respects_local_weighting -- --exact --nocapture` |
| Adversarial multi-operator open-market qualification remains bounded and fail closed: invalid mirrored listing signatures stay visible but untrusted, divergent replica freshness blocks admission, imported reputation remains locally weighted, and governance or penalty evaluation rejects trust activations not issued by the governing local operator | `crates/arc-core/src/listing.rs`, `crates/arc-core/src/governance.rs`, `crates/arc-core/src/open_market.rs`, and `crates/arc-cli/tests/certify.rs` | `CARGO_INCREMENTAL=0 cargo test -p arc-core --lib generic_listing_search_rejects_reports_with_invalid_listing_signatures -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-core --lib non_local_activation_authority -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test certify certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust -- --exact --nocapture` |
| SPIFFE/SVID-style workload identity maps into runtime attestation, policy, issuance, and governed receipts without silently widening opaque verifier identity | `crates/arc-core/src/capability.rs` parsing/binding unit coverage, `crates/arc-policy/src/evaluate/tests.rs` workload-identity policy regressions, `crates/arc-cli/src/issuance.rs` issuance fail-closed regression compiled through `arc-control-plane`, and `crates/arc-kernel/src/lib.rs` governed runtime/receipt regressions | `cargo test -p arc-core workload_identity -- --nocapture && cargo test -p arc-policy tool_access_workload_identity -- --nocapture && cargo test -p arc-control-plane workload_identity_validation_denies_conflicting_attestation_without_policy -- --nocapture && cargo test -p arc-kernel governed_request_denies_conflicting_workload_identity_binding -- --nocapture && cargo test -p arc-kernel governed_monetary_allow_records_runtime_assurance_metadata -- --nocapture` |
| Azure Attestation JWTs, AWS Nitro attestation documents, and Google Confidential VM JWTs normalize into one canonical ARC appraisal boundary without silently widening unsupported evidence above `attested` | `crates/arc-core/src/appraisal.rs` canonical appraisal coverage plus `crates/arc-control-plane/src/attestation.rs` Azure, Nitro, and Google verifier coverage over issuer trust, certificate or `JWKS` validation, freshness, measurements, secure-boot posture, and optional workload-identity projection | `cargo test -p arc-core appraisal -- --nocapture && cargo test -p arc-control-plane azure_maa -- --nocapture && cargo test -p arc-control-plane aws_nitro -- --nocapture && cargo test -p arc-control-plane google_confidential_vm -- --nocapture` |
| Explicit attestation trust policy can rebind trusted Azure, AWS Nitro, and Google verifier evidence into stronger runtime-assurance tiers while rejecting stale or unmatched verifier evidence fail closed | `crates/arc-core/src/capability.rs` trust-policy resolver coverage, `crates/arc-policy/src/validate.rs` trusted-verifier validation, `crates/arc-control-plane/src/attestation.rs` policy-bound verifier tests, `crates/arc-kernel/src/lib.rs` governed-runtime trust-policy regressions, and [WORKLOAD_IDENTITY_RUNBOOK.md](../WORKLOAD_IDENTITY_RUNBOOK.md) | `cargo test -p arc-core runtime_attestation_trust_policy -- --nocapture && cargo test -p arc-policy runtime_assurance_validation -- --nocapture && cargo test -p arc-control-plane runtime_assurance_policy -- --nocapture && cargo test -p arc-kernel governed_request_denies_untrusted_attestation_when_trust_policy_is_configured -- --nocapture && cargo test -p arc-kernel governed_monetary_allow_rebinds_trusted_attestation_to_verified -- --nocapture && cargo test -p arc-kernel governed_monetary_allow_rebinds_google_attestation_to_verified -- --nocapture` |
| Operators can export one signed runtime-attestation appraisal report that captures verifier family, evidence descriptor, normalized assertions, vendor-scoped claims, and policy-visible outcome without claiming generic attestation-result interoperability | `crates/arc-cli/src/trust_control.rs` appraisal export surface, `crates/arc-cli/src/main.rs` CLI export path, `crates/arc-cli/tests/receipt_query.rs` remote plus local export regression, and [WORKLOAD_IDENTITY_RUNBOOK.md](../WORKLOAD_IDENTITY_RUNBOOK.md) | `cargo test -p arc-cli --test receipt_query test_runtime_attestation_appraisal_export_surfaces -- --exact --nocapture` |
| Operators can exchange one signed runtime-attestation appraisal result artifact and evaluate imported results only through explicit local issuer, signer, freshness, verifier-family, and portable-claim policy mapping across the shipped Azure/AWS Nitro/Google bridge families | `crates/arc-core/src/appraisal.rs` result/import contract, `crates/arc-cli/src/trust_control.rs` import or export surfaces, and `crates/arc-cli/tests/receipt_query.rs` mixed-provider result qualification plus fail-closed stale, unsupported-family, and contradictory-claim regressions | `cargo test -p arc-core appraisal -- --nocapture && cargo test -p arc-cli --test receipt_query test_runtime_attestation_appraisal_result_import_export_surfaces -- --exact --nocapture && cargo test -p arc-cli --test receipt_query test_runtime_attestation_appraisal_result_qualification_covers_mixed_providers_and_fail_closed_imports -- --exact --nocapture` |
| Portable verifier descriptors, reference-value sets, and trust bundles remain signed, versioned, and fail closed on stale, ambiguous, or contract-mismatched verifier metadata | `crates/arc-core/src/appraisal.rs` verifier descriptor, reference-value, and trust-bundle contract plus bounded validation regressions, and [WORKLOAD_IDENTITY_RUNBOOK.md](../WORKLOAD_IDENTITY_RUNBOOK.md) | `cargo test -p arc-core trust_bundle -- --nocapture` |
| Public issuer/verifier discovery remains signed, freshness-bounded, transparent, and informational-only, with missing authority material or incomplete discovery data failing closed instead of widening local trust from visibility | `crates/arc-credentials/src/discovery.rs` discovery-contract validation and `crates/arc-cli/tests/passport.rs` public discovery regressions | `cargo test -p arc-credentials signed_public_ -- --nocapture && CARGO_INCREMENTAL=0 cargo test -p arc-cli --test passport public_discovery -- --nocapture` |
| Cross-issuer passport portfolios remain provenance-preserving, explicit about migration, and fail closed when visibility is mistaken for local trust activation | `crates/arc-credentials/src/cross_issuer.rs` contract plus `crates/arc-credentials/src/tests.rs` cross-issuer portfolio, migration, and trust-pack regressions | `cargo test -p arc-credentials cross_issuer_ -- --nocapture` |
| ARC now ships one bounded public identity profile, verifier-bound wallet-directory entry, replay-safe wallet-routing manifest, and identity-interop qualification matrix over `did:arc` plus explicit `did:web`, `did:key`, and `did:jwk` compatibility inputs, with unsupported methods, unsupported credential families, directory poisoning, route replay, and cross-operator issuer mismatch all failing closed | `crates/arc-core/src/identity_network.rs` plus the `docs/standards/ARC_PUBLIC_IDENTITY_*` artifacts | `CARGO_TARGET_DIR=target/identity-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p arc-core --lib && CARGO_TARGET_DIR=target/identity-test CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-core --lib identity_network -- --nocapture && for f in docs/standards/ARC_PUBLIC_IDENTITY_PROFILE.json docs/standards/ARC_PUBLIC_WALLET_DIRECTORY_ENTRY_EXAMPLE.json docs/standards/ARC_PUBLIC_WALLET_ROUTING_EXAMPLE.json docs/standards/ARC_PUBLIC_IDENTITY_QUALIFICATION_MATRIX.json; do jq empty \"$f\"; done` |
| ARC now ships one bounded `arc-link` runtime over pinned Base and standby Arbitrum operator inventory, Chainlink primary plus Pyth fallback reads, sequencer down or recovery gating, explicit pause or disable controls, bounded degraded stale-cache grace, runtime health reporting, and conservative receipt-side cross-currency conversion margins | `crates/arc-link/src/lib.rs`, `crates/arc-link/src/config.rs`, `crates/arc-link/src/sequencer.rs`, `crates/arc-link/src/monitor.rs`, `crates/arc-kernel/src/lib.rs`, `docs/standards/ARC_LINK_PROFILE.md`, `docs/standards/ARC_LINK_BASE_MAINNET_CONFIG.json`, `docs/standards/ARC_LINK_MONITOR_REPORT_EXAMPLE.json`, `docs/standards/ARC_LINK_QUALIFICATION_MATRIX.json`, and `docs/standards/ARC_LINK_KERNEL_RECEIPT_POLICY.md` | `CARGO_TARGET_DIR=target/arc-link-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-link -- --test-threads=1 && CARGO_TARGET_DIR=target/arc-kernel-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-kernel cross_currency -- --test-threads=1 && for f in docs/standards/ARC_LINK_BASE_MAINNET_CONFIG.json docs/standards/ARC_LINK_MONITOR_REPORT_EXAMPLE.json docs/standards/ARC_LINK_QUALIFICATION_MATRIX.json; do jq empty \"$f\"; done` |
| ARC now ships one bounded `arc-anchor` runtime over official Base or Arbitrum root publication, explicit publisher-authorization and sequence guards, OpenTimestamps super-root linkage, Solana memo normalization, `did:arc` discovery projection, and fail-closed shared proof bundles across the supported lanes | `crates/arc-anchor/src/lib.rs`, `crates/arc-anchor/src/evm.rs`, `crates/arc-anchor/src/bitcoin.rs`, `crates/arc-anchor/src/solana.rs`, `crates/arc-anchor/src/bundle.rs`, `crates/arc-anchor/src/discovery.rs`, `docs/standards/ARC_ANCHOR_PROFILE.md`, `docs/standards/ARC_ANCHOR_DISCOVERY_EXAMPLE.json`, `docs/standards/ARC_ANCHOR_OTS_SUBMISSION_EXAMPLE.json`, `docs/standards/ARC_ANCHOR_SOLANA_MEMO_EXAMPLE.json`, `docs/standards/ARC_ANCHOR_PROOF_BUNDLE_EXAMPLE.json`, and `docs/standards/ARC_ANCHOR_QUALIFICATION_MATRIX.json` | `CARGO_TARGET_DIR=target/arc-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-anchor -- --test-threads=1 && pnpm --dir contracts devnet:smoke && for f in docs/standards/ARC_ANCHOR_DISCOVERY_EXAMPLE.json docs/standards/ARC_ANCHOR_OTS_SUBMISSION_EXAMPLE.json docs/standards/ARC_ANCHOR_SOLANA_MEMO_EXAMPLE.json docs/standards/ARC_ANCHOR_PROOF_BUNDLE_EXAMPLE.json docs/standards/ARC_ANCHOR_QUALIFICATION_MATRIX.json; do jq empty \"$f\"; done` |
| ARC now ships one bounded Functions fallback, automation-job, CCIP settlement-coordination, and payment-interop surface over the official web3 runtime stack, with DON rejection, replay drift, duplicate delivery, unsupported-chain routing, implicit custody, and implicit gas sponsorship all failing closed | `crates/arc-anchor/src/functions.rs`, `crates/arc-anchor/src/automation.rs`, `crates/arc-settle/src/automation.rs`, `crates/arc-settle/src/ccip.rs`, `crates/arc-settle/src/payments.rs`, `docs/standards/ARC_FUNCTIONS_FALLBACK_PROFILE.md`, `docs/standards/ARC_AUTOMATION_PROFILE.md`, `docs/standards/ARC_CCIP_PROFILE.md`, `docs/standards/ARC_PAYMENT_INTEROP_PROFILE.md`, `docs/standards/ARC_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json`, and `docs/release/ARC_WEB3_INTEROP_RUNBOOK.md` | `CARGO_TARGET_DIR=target/arc-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-anchor -- --test-threads=1 && CARGO_TARGET_DIR=target/arc-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-settle --lib -- --test-threads=1 && CARGO_TARGET_DIR=target/arc-settle-runtime CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-settle --test runtime_devnet -- --nocapture && for f in docs/standards/ARC_FUNCTIONS_REQUEST_EXAMPLE.json docs/standards/ARC_FUNCTIONS_RESPONSE_EXAMPLE.json docs/standards/ARC_ANCHOR_AUTOMATION_JOB_EXAMPLE.json docs/standards/ARC_SETTLEMENT_WATCHDOG_JOB_EXAMPLE.json docs/standards/ARC_CCIP_MESSAGE_EXAMPLE.json docs/standards/ARC_CCIP_RECONCILIATION_EXAMPLE.json docs/standards/ARC_X402_REQUIREMENTS_EXAMPLE.json docs/standards/ARC_EIP3009_TRANSFER_WITH_AUTHORIZATION_EXAMPLE.json docs/standards/ARC_CIRCLE_NANOPAYMENT_EXAMPLE.json docs/standards/ARC_4337_PAYMASTER_COMPAT_EXAMPLE.json docs/standards/ARC_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json; do jq empty \"$f\"; done` |
| ARC now ships one bounded web3 operations contract over oracle, anchor, and settlement runtime reports, indexer lag/drift or replay visibility, explicit emergency modes that narrow publication and dispatch authority fail closed, and persisted control-state or control-trace evidence for every exercised posture change | `crates/arc-anchor/src/ops.rs`, `crates/arc-settle/src/ops.rs`, `crates/arc-control-plane/tests/web3_ops_qualification.rs`, `docs/standards/ARC_WEB3_OPERATIONS_PROFILE.md`, `target/web3-ops-qualification/runtime-reports/`, `target/web3-ops-qualification/control-state/`, `target/web3-ops-qualification/control-traces/`, `target/web3-ops-qualification/incident-audit.json`, `docs/standards/ARC_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json`, and `docs/release/ARC_WEB3_OPERATIONS_RUNBOOK.md` | `./scripts/qualify-web3-ops-controls.sh && for f in docs/standards/ARC_ANCHOR_RUNTIME_REPORT_EXAMPLE.json docs/standards/ARC_SETTLE_RUNTIME_REPORT_EXAMPLE.json docs/standards/ARC_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json; do jq empty \"$f\"; done` |
| ARC now ships one generated end-to-end settlement proof lane over FX-backed dual-sign execution, timeout refund, canonical-drift reorg detection, and bond impair/expiry recovery, with a stable hosted reviewer bundle under `target/release-qualification/web3-runtime/e2e/` | `crates/arc-settle/tests/web3_e2e_qualification.rs`, `scripts/qualify-web3-e2e.sh`, `target/web3-e2e-qualification/partner-qualification.json`, `target/web3-e2e-qualification/scenarios/`, `docs/standards/ARC_SETTLE_QUALIFICATION_MATRIX.json`, and `docs/release/ARC_WEB3_PARTNER_PROOF.md` | `./scripts/qualify-web3-e2e.sh && jq empty docs/standards/ARC_SETTLE_QUALIFICATION_MATRIX.json docs/standards/ARC_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json` |
| ARC now ships one reproducible web3 runtime-qualification lane, one reviewed-manifest deployment runner, one approval artifact family, and one rollback-plan surface that keep promotion explicit, reproducible, and fail closed | `scripts/qualify-web3-promotion.sh`, `contracts/scripts/promote-deployment.mjs`, `contracts/deployments/local-devnet.reviewed.json`, `docs/standards/ARC_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json`, `docs/standards/ARC_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json`, `docs/standards/ARC_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`, and `docs/release/ARC_WEB3_DEPLOYMENT_PROMOTION.md` | `./scripts/qualify-web3-promotion.sh && jq empty docs/standards/ARC_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json docs/standards/ARC_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json docs/standards/ARC_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json` |
| ARC now ships one reproducible web3 qualification lane, one deployment-promotion policy with explicit gas and latency budgets, and one focused readiness audit that keep local qualification, reviewed manifests, and external publication holds distinct | `scripts/qualify-web3-runtime.sh`, `scripts/qualify-web3-promotion.sh`, `docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json`, `docs/release/ARC_WEB3_READINESS_AUDIT.md`, and `docs/release/ARC_WEB3_DEPLOYMENT_PROMOTION.md` | `./scripts/qualify-web3-runtime.sh && ./scripts/qualify-web3-promotion.sh && jq empty docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json` |
| ARC now ships one partner-visible full-ladder web3 proof package that lets reviewers trace contracts, oracle, anchor, settlement, interop, and ops evidence end to end while keeping remaining external dependencies explicit | `docs/standards/ARC_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json`, `docs/release/ARC_WEB3_PARTNER_PROOF.md`, and `docs/release/ARC_WEB3_READINESS_AUDIT.md` | `jq empty docs/standards/ARC_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json && ./scripts/qualify-web3-runtime.sh` |
| Hosted release qualification now executes the bounded web3 runtime, end-to-end settlement, ops-control, and promotion lanes and stages stable hosted web3 evidence paths alongside the existing release corpus | `.github/workflows/release-qualification.yml`, `scripts/stage-web3-release-artifacts.sh`, `target/release-qualification/web3-runtime/`, `target/release-qualification/web3-runtime/e2e/`, and `target/release-qualification/web3-runtime/ops/` | `bash -n scripts/stage-web3-release-artifacts.sh scripts/qualify-web3-runtime.sh scripts/qualify-web3-e2e.sh scripts/qualify-web3-ops-controls.sh scripts/qualify-web3-promotion.sh && rg -n 'Hosted web3 runtime qualification|Hosted web3 promotion qualification|Stage hosted web3 qualification artifacts|retention-days' .github/workflows/release-qualification.yml` |
| Wrapped/runtime MCP compatibility remains truthful across live peer waves | live conformance results under `target/release-qualification/conformance/` | `./scripts/qualify-release.sh` |

Lean proof artifacts are informative, but they are not a release gate until the
root-imported proof surface is aligned with the shipped runtime and free of
`sorry`.

## Release Rule

Do not tag or announce a production candidate from a green workspace run alone.

Release readiness for the current surface requires:

1. `./scripts/ci-workspace.sh` green
2. `./scripts/check-sdk-parity.sh` green
3. `./scripts/check-web3-contract-parity.sh` green
4. `./scripts/qualify-release.sh` green
5. the explicit MSRV lane in `.github/workflows/ci.yml` green on Rust `1.93.0`
6. [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md),
   [RELEASE_AUDIT.md](RELEASE_AUDIT.md), and
   [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) updated together
7. [OBSERVABILITY.md](OBSERVABILITY.md),
   [GA_CHECKLIST.md](GA_CHECKLIST.md), and
   [RISK_REGISTER.md](RISK_REGISTER.md) updated together

If a hosted CI run cannot be observed from the current environment, record that
as an explicit procedural note in the release audit instead of implying it
happened.

When hosted `Release Qualification` is observed, reviewers should expect the
web3-specific hosted evidence under `target/release-qualification/web3-runtime/`,
including the staged `logs/qualification.log`,
`logs/promotion-qualification.log`, `logs/e2e-qualification.log`,
`logs/ops-qualification.log`, the generated `e2e/` and `ops/` bundles,
promotion reports under `promotion/`, contract reports, deployment snapshots,
and copied web3 release-doc snapshots.
