status: passed

# Phase 174 Verification

## Outcome

Phase `174` is complete. ARC now ships a bounded reviewed-manifest deployment
runner, explicit approval/promote/rollback artifacts, reproducible CREATE2
promotion qualification, and hosted staging for the resulting promotion
evidence.

## Evidence

- `contracts/scripts/promote-deployment.mjs`
- `contracts/scripts/qualify-promotion.mjs`
- `contracts/deployments/local-devnet.reviewed.json`
- `docs/standards/ARC_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json`
- `docs/standards/ARC_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json`
- `docs/standards/ARC_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`
- `scripts/qualify-web3-promotion.sh`
- `.github/workflows/release-qualification.yml`
- `scripts/stage-web3-release-artifacts.sh`
- `target/web3-promotion-qualification/promotion-qualification.json`
- `target/release-qualification/web3-runtime/promotion/promotion-qualification.json`
- `.planning/phases/174-live-deployment-runner-promotion-approvals-and-reproducible-rollout/174-01-SUMMARY.md`
- `.planning/phases/174-live-deployment-runner-promotion-approvals-and-reproducible-rollout/174-02-SUMMARY.md`
- `.planning/phases/174-live-deployment-runner-promotion-approvals-and-reproducible-rollout/174-03-SUMMARY.md`

## Validation

- `chmod +x scripts/qualify-web3-promotion.sh`
- `bash -n scripts/qualify-web3-promotion.sh scripts/qualify-web3-runtime.sh scripts/stage-web3-release-artifacts.sh`
- `jq empty docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json docs/standards/ARC_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json docs/standards/ARC_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json docs/standards/ARC_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json docs/standards/ARC_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`
- `./scripts/qualify-web3-promotion.sh`
- `./scripts/qualify-web3-runtime.sh`
- `./scripts/stage-web3-release-artifacts.sh`
- `jq empty target/release-qualification/web3-runtime/artifact-manifest.json`
- `find target/release-qualification/web3-runtime -type f | sort`
- `git diff --check`

## Requirement Closure

- `W3REL-02` complete

## Next Step

Phase `175`: Generated Runtime Reports and Exercisable Emergency Controls.
