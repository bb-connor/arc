# ARC Web3 Operations Runbook

## Purpose

This runbook covers the shared operations contract introduced in phase `165`
for the shipped `arc-link`, `arc-anchor`, and `arc-settle` runtimes.

Use the component-specific runbooks for normal steady-state procedures:

- `docs/release/ARC_LINK_RUNBOOK.md`
- `docs/release/ARC_ANCHOR_RUNBOOK.md`
- `docs/release/ARC_SETTLE_RUNBOOK.md`

Use this runbook when an incident spans more than one web3 component.

## First Response

1. Pull the latest component reports:
   - local: `target/web3-ops-qualification/runtime-reports/arc-link-runtime-report.json`
   - local: `target/web3-ops-qualification/runtime-reports/arc-anchor-runtime-report.json`
   - local: `target/web3-ops-qualification/runtime-reports/arc-settle-runtime-report.json`
   - hosted staged copy: `target/release-qualification/web3-runtime/ops/runtime-reports/`
2. Pull the latest control evidence:
   - `target/web3-ops-qualification/control-state/`
   - `target/web3-ops-qualification/control-traces/`
   - hosted staged copy: `target/release-qualification/web3-runtime/ops/control-state/`
   - hosted staged copy: `target/release-qualification/web3-runtime/ops/control-traces/`
3. Identify which component first observed canonical drift:
   - oracle data quality or sequencer outage in `arc-link`
   - root-registry or checkpoint replay in `arc-anchor`
   - settlement finality or receipt disappearance in `arc-settle`
4. Narrow write authority before continuing:
   - `arc-link`: global pause or pair/chain disable
   - `arc-anchor`: `publish_paused` or `recovery_only`
   - `arc-settle`: `dispatch_paused`, `refund_only`, or `recovery_only`

## Incident Classes

### Oracle Instability

Symptoms:

- `arc-link` emits `critical` pause, sequencer, or divergence alerts
- affected pair health is `tripped`, `paused`, or `unavailable`

Response:

1. Pause cross-currency resolution or disable the affected pair or chain.
2. Keep same-currency settlement open only if the settlement lane does not
   depend on that conversion.
3. Do not resume anchor or settlement automation that depends on the affected
   conversion until `arc-link` returns to a healthy report.

### Anchor Drift Or Replay

Symptoms:

- `arc-anchor` indexers are `drifted` or `replaying`
- the primary EVM lane is `recovering`
- incidents reference `root_registry_reorg` or canonical checkpoint mismatch

Response:

1. Move `arc-anchor` into `recovery_only`.
2. Stop new root publication and stop importing secondary proofs.
3. Replay the root-registry indexer against the canonical chain head.
4. Resume secondary proof import only after the primary EVM lane is healthy.

### Settlement Reorg Or Finality Drift

Symptoms:

- `arc-settle` reports `reorged`, `awaiting_confirmations`, or
  `awaiting_dispute_window`
- settlement indexers are `replaying` or materially `drifted`

Response:

1. Move `arc-settle` into `refund_only` if beneficiary release is no longer
   safe, or `recovery_only` if existing lanes still need controlled replay.
2. Keep new escrow creation paused until the recovery queue is empty.
3. Rebuild Merkle release or refund state against the canonical anchor proof.
4. Only resume dispatch after the runtime report returns to `healthy`.

## Recovery Completion

Web3 incident recovery is complete when all of the following are true:

- `arc-link` has no unresolved `critical` alert for the affected chain or pair
- `arc-anchor` primary EVM lane is not `recovering`, `drifted`, or `failed`
- `arc-settle` has no queued reorg recoveries for the affected chain
- the local qualification lane is green:
  - `./scripts/qualify-web3-ops-controls.sh`
  - `target/web3-ops-qualification/incident-audit.json`
  - `pnpm --dir contracts devnet:smoke`
  - `CARGO_TARGET_DIR=target/arc-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-anchor -- --test-threads=1`
  - `CARGO_TARGET_DIR=target/arc-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-settle -- --test-threads=1`
- the hosted staged bundle is refreshed when release qualification is being prepared:
  - `target/release-qualification/web3-runtime/ops/incident-audit.json`
  - `target/release-qualification/web3-runtime/logs/ops-qualification.log`

## Non-Claims

- This runbook does not claim hosted dashboards, paging integration, or
  external SIEM export.
- This runbook does not replace sanctions review, wallet control, or legal
  dispute handling.
- This runbook does not imply that local recovery evidence alone is enough for
  public release promotion.
