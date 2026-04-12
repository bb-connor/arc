# ARC Web3 Readiness Audit

## Purpose

This audit closes phase `166` for ARC's bounded web3 runtime stack.

It is intentionally narrower than the repository-wide release audit. The goal
here is to answer one question only: is the shipped web3 stack ready for
promotion from local qualification to operator-reviewed deployment templates?

## Decision

**Decision:** local web3-runtime and reviewed-promotion go, external
deployment hold.

Meaning:

- the repo now has one reproducible web3 qualification entrypoint:
  `./scripts/qualify-web3-runtime.sh`
- the repo now also has one reproducible ops-control drill lane:
  `./scripts/qualify-web3-ops-controls.sh`
- the repo now also has one reproducible partner-facing settlement lane:
  `./scripts/qualify-web3-e2e.sh`
- the repo now also has one reproducible reviewed-manifest promotion lane:
  `./scripts/qualify-web3-promotion.sh`
- the contract family, oracle runtime, anchor runtime, settlement runtime,
  and interop overlays all have explicit qualification artifacts
- runtime qualification now emits generated runtime reports, persisted
  control-state snapshots, append-only control traces, and one incident audit
  under `target/web3-ops-qualification/` and stages the same family into the
  hosted web3 bundle
- runtime qualification now also emits one generated end-to-end settlement
  proof bundle under `target/web3-e2e-qualification/` and stages the same
  family into `target/release-qualification/web3-runtime/e2e/`
- gas and latency budgets are frozen in
  `docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json`
- reviewed-manifest promotion now emits explicit approval, deployment-report,
  and rollback-plan artifacts
- mainnet publication remains blocked on hosted workflow observation and
  operator-owned target-chain approval material

## Security And Invariant Review

| Area | State | Disposition |
| --- | --- | --- |
| Contract proof, signature, delegate, stale-feed, and timeout invariants | reviewed | closed through `contracts/reports/ARC_WEB3_CONTRACT_SECURITY_REVIEW.md` and local-devnet qualification |
| Runtime observability, replay, and pause controls | reviewed | closed through `docs/standards/ARC_WEB3_OPERATIONS_PROFILE.md` and `docs/release/ARC_WEB3_OPERATIONS_RUNBOOK.md` |
| On-chain Ed25519 verification | absent | accepted non-goal; identity binding remains registry-backed and explicit |
| Sanctions or blacklist screening | absent | operator obligation outside the shipped local runtime lane |
| Live CREATE2 deployment runner | present | closed through `contracts/scripts/promote-deployment.mjs`, `./scripts/qualify-web3-promotion.sh`, and explicit approval/rollback artifacts |
| Proxy upgrade path | absent | accepted by design; replacement deployments remain the remediation path |

## Measured Budgets

Measured local-devnet gas comes from
`contracts/reports/local-devnet-qualification.json`.

| Operation | Measured | Budget | Status |
| --- | ---: | ---: | --- |
| `registerOperator` | 74,658 | 80,000 | pass |
| `registerDelegate` | 74,559 | 80,000 | pass |
| `publishRoot` | 172,426 | 190,000 | pass |
| `registerFeed` | 123,625 | 140,000 | pass |
| `getPrice` | 60,173 | 70,000 | pass |
| `createEscrow` | 305,476 | 330,000 | pass |
| `partialReleaseWithProofDetailed` | 103,764 | 120,000 | pass |
| `releaseWithSignature` | 76,289 | 90,000 | pass |
| `lockBond` | 299,787 | 320,000 | pass |
| `releaseBondDetailed` | 83,260 | 90,000 | pass |

Operational latency and drift budgets are also explicit:

- oracle refresh interval: `60s`
- bounded oracle max age: `600s`
- sequencer recovery grace: `300s`
- anchor indexer drift threshold: `3` checkpoints
- settlement indexer drift threshold: `12` blocks
- CCIP validity windows must remain at least `2x` the expected delivery latency

## Promotion Gate

Promotion from local devnet to operator-reviewed templates is allowed only
when:

1. `./scripts/qualify-web3-runtime.sh` is green.
2. `./scripts/qualify-web3-e2e.sh` is green.
3. `./scripts/qualify-web3-promotion.sh` is green.
4. The reviewed manifest and approval artifact bind the same manifest hash,
   release id, deployment policy id, and CREATE2 salt namespace.
5. Replayed promotion over fresh local devnets yields identical CREATE2-planned
   and deployed addresses.
6. Failed promotion emits an explicit rollback plan, and local rehearsal proves
   snapshot rollback can execute fail closed.
7. The operator has reviewed `contracts/deployments/base-mainnet.template.json`
   or `contracts/deployments/arbitrum-one.template.json` and filled the
   placeholder addresses intentionally.
8. Web3-enabled runtime policy uses local durable receipt persistence with
   checkpoint issuance enabled; append-only remote receipt mirrors do not
   satisfy the promotion gate for Merkle or Solana evidence lanes.
9. The web3 operations and settlement/anchor/oracle runbooks are updated
   together with the candidate docs.
10. The measured gas table stays within the deployment policy budgets.

Promotion from template review to actual public deployment is still blocked
until:

1. hosted `Release Qualification` results are observed on the candidate
   revision, including the staged artifact bundle under
   `target/release-qualification/web3-runtime/` and the generated ops-control
   evidence under `target/release-qualification/web3-runtime/ops/` plus the
   staged end-to-end settlement package under
   `target/release-qualification/web3-runtime/e2e/`, and
2. the operator produces one environment-specific reviewed manifest and
   approval artifact with a predeployed CREATE2 factory address, and
3. operator RPC and deployer key material are supplied outside the repo for
   the target chain.

## Evidence

- `./scripts/qualify-web3-runtime.sh`
- `./scripts/qualify-web3-e2e.sh`
- `./scripts/qualify-web3-ops-controls.sh`
- `./scripts/qualify-web3-promotion.sh`
- `.github/workflows/release-qualification.yml`
- `./scripts/stage-web3-release-artifacts.sh`
- `target/web3-e2e-qualification/partner-qualification.json`
- `target/web3-e2e-qualification/scenarios/fx-dual-sign-settlement.json`
- `target/web3-e2e-qualification/scenarios/reorg-recovery.json`
- `target/web3-ops-qualification/incident-audit.json`
- `target/web3-ops-qualification/runtime-reports/arc-link-runtime-report.json`
- `target/web3-ops-qualification/runtime-reports/arc-anchor-runtime-report.json`
- `target/web3-ops-qualification/runtime-reports/arc-settle-runtime-report.json`
- `contracts/deployments/local-devnet.reviewed.json`
- `contracts/reports/local-devnet-qualification.json`
- `contracts/reports/ARC_WEB3_CONTRACT_SECURITY_REVIEW.md`
- `contracts/reports/ARC_WEB3_CONTRACT_GAS_AND_STORAGE.md`
- `docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json`
- `docs/standards/ARC_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json`
- `docs/standards/ARC_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json`
- `docs/standards/ARC_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`
- `docs/standards/ARC_WEB3_OPERATIONS_PROFILE.md`
- `docs/release/ARC_WEB3_OPERATIONS_RUNBOOK.md`
