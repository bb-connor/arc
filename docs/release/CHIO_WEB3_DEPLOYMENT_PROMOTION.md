# Chio Web3 Deployment Promotion

## Purpose

This document closes the reproducible promotion slice of phase `174`.

It defines how the shipped bounded web3 stack moves from local qualification
to reviewed-manifest rollout without implying unattended public-chain
deployment.

## Promotion Inputs

The bounded runner takes three explicit inputs:

- one reviewed deployment manifest
- one approval artifact that binds the exact manifest hash and shipped package
- one output directory that persists the promotion report, deployment record,
  and rollback plan

For local rehearsal those inputs are:

- `contracts/deployments/local-devnet.reviewed.json`
- a generated approval artifact under `target/web3-promotion-qualification/`
- `--local-devnet --rollback-on-failure`

For operator rollout the reviewed manifest is derived from one shipped template:

- `contracts/deployments/base-mainnet.template.json`
- `contracts/deployments/arbitrum-one.template.json`

The approval artifact must bind:

- `candidate_release_id`
- `deployment_policy_id`
- `reviewed_manifest_path`
- `reviewed_manifest_sha256`
- `environment`
- `create2.factory_mode`
- `create2.factory_address` for non-local rollout
- `create2.salt_namespace`
- explicit approver identities and timestamps
- explicit failure policy

## Promotion Stages

### 1. Runtime Qualification

Run:

```bash
./scripts/qualify-web3-runtime.sh
```

Required evidence:

- `contracts/reports/local-devnet-qualification.json`
- `target/web3-runtime-qualification/qualification.log`
- `docs/release/CHIO_WEB3_READINESS_AUDIT.md`

### 2. Promotion Qualification

Run:

```bash
./scripts/qualify-web3-promotion.sh
```

Required evidence:

- `target/web3-promotion-qualification/promotion-qualification.json`
- `target/web3-promotion-qualification/run-a/promotion-report.json`
- `target/web3-promotion-qualification/run-a/rollback-plan.json`
- `target/web3-promotion-qualification/run-b/promotion-report.json`
- `target/web3-promotion-qualification/negative-approval/promotion-report.json`
- `target/web3-promotion-qualification/negative-rollback/rollback-plan.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`

This lane proves three invariants:

- the same reviewed manifest produces identical CREATE2-planned and deployed
  addresses across fresh local devnets
- tampered approval artifacts fail closed before deployment begins
- failed local promotion emits an explicit rollback plan and executes snapshot
  rollback when the runner is asked to do so

### 3. Runtime Devnet Rehearsal

Use the runtime devnet harness when the operator wants end-to-end rehearsal
over the settlement runtime rather than contract-only smoke coverage.

Required evidence:

- `contracts/deployments/runtime-devnet.json`
- `cargo test -p chio-settle --test runtime_devnet -- --nocapture`

### 4. Reviewed Manifest Rollout

Local rehearsal command:

```bash
node contracts/scripts/promote-deployment.mjs \
  --manifest contracts/deployments/local-devnet.reviewed.json \
  --approval target/web3-promotion-qualification/run-a/approval.json \
  --output-dir target/web3-promotion-qualification/manual-run \
  --local-devnet \
  --rollback-on-failure
```

Operator rollout command shape:

```bash
node contracts/scripts/promote-deployment.mjs \
  --manifest contracts/deployments/base-mainnet.reviewed.json \
  --approval approvals/base-mainnet.approval.json \
  --output-dir target/web3-live-rollout/base-mainnet \
  --rpc-url "$CHIO_BASE_RPC_URL" \
  --deployer-key "$CHIO_BASE_DEPLOYER_KEY" \
  --registry-admin-key "$CHIO_BASE_REGISTRY_ADMIN_KEY" \
  --operator-key "$CHIO_BASE_OPERATOR_KEY" \
  --price-admin-key "$CHIO_BASE_PRICE_ADMIN_KEY"
```

Prepare one reviewed chain manifest from one shipped template:

- `contracts/deployments/base-mainnet.template.json`
- `contracts/deployments/arbitrum-one.template.json`

Required review points:

- registry-admin, price-admin, and operator addresses are filled explicitly
- settlement token address matches the intended jurisdiction and custody model
- CREATE2 salts remain unchanged from the shipped package unless a new version
  is cut intentionally
- the reviewed manifest hash recorded in the approval artifact matches the file
  sent to the runner exactly
- non-local rollout uses one predeployed CREATE2 factory address recorded in
  the approval artifact
- if deployer, registry admin, operator, and price admin are distinct, the
  runner must receive signer keys for those reviewed roles explicitly
- deferred capabilities in
  `docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json` remain deferred unless a
  separate milestone reopens them

### 5. Hosted Publication Gate

Public deployment remains held outside the repo-local gate until:

- hosted workflow observation is attached to the candidate revision
- the staged hosted artifact bundle under `target/release-qualification/web3-runtime/`
  includes both runtime and promotion qualification evidence
- the operator approves the exact reviewed manifest and target-chain rollout
  explicitly

## Rollback Rule

If any promotion stage fails, return to the last qualified stage and keep the
later stage blocked.

Examples:

- over-budget gas on a new contract build: return to local qualification
- approval artifact mismatch: stop before any deployment transaction is sent
- reviewed-manifest CREATE2 drift: stop and recut the manifest or package
- runtime-devnet replay or reorg mismatch: return to local qualification and
  re-run the rehearsal only after recovery
- missing live-chain RPC, deployer key, or predeployed CREATE2 factory:
  stop before any live chain work

Local rollback semantics:

- the local runner captures an EVM snapshot after dependency and factory setup
- failed local promotion can execute `evm_revert` and mark
  `rollback_executed: true`

Operator rollback semantics:

- live rollback is replacement-oriented, not proxy-upgrade-oriented
- stop broader promotion immediately
- retain the reviewed manifest, approval, report, and rollback plan
- recut a superseding reviewed manifest if remediation is required

## Non-Claims

- This document does not claim that Chio performs unattended testnet or mainnet
  deployment.
- This document does not replace custody, sanctions, or legal review required
  by the operator.
- This document does not override the repository-wide release rule that hosted
  workflow results must still be observed before external publication.
- This document does not claim that operator RPC credentials, deployer keys, or
  predeployed CREATE2 factories belong in the repo.
