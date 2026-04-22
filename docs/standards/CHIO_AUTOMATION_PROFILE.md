# Chio Web3 Automation Profile

## Purpose

This profile closes phase `162` by freezing Chio's bounded automation surface
over anchoring and settlement watchdog jobs.

The shipped automation lane is declarative and replay-safe. It lets operators
schedule work that Chio can already describe explicitly, but it does not turn
keepers, forwarders, or schedulers into ambient authority.

## Shipped Boundary

Chio now ships two bounded automation job families:

- `chio.anchor-automation-job.v1` for primary EVM root publication
- `chio.settlement-automation-job.v1` for settlement finality or timeout
  observation and bond-expiry watchdogs

All shipped jobs share these rules:

- each job carries one state fingerprint that must still match at execution
- each job carries one bounded replay window in seconds
- duplicate suppression and delayed-safe execution are explicit outcomes, not
  implicit retries
- operator override remains required for the shipped anchor and settlement
  flows
- delegate-forwarder use must stay visible through a prepared delegate
  registration artifact

## Supported Job Types

The current runtime supports:

- cron-driven anchor publication over one prepared EVM root-publication call
- cron-driven settlement finality observation over one prepared dispatch
- cron-driven bond-expiry observation over one named vault reference

The profile does not claim ambient log-triggers, arbitrary custom logic, or
operator-free automatic releases even though those enum variants exist as
future-compatible shape.

## Reference Artifacts

- `docs/standards/CHIO_ANCHOR_AUTOMATION_JOB_EXAMPLE.json`
- `docs/standards/CHIO_SETTLEMENT_WATCHDOG_JOB_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json`

## Failure Posture

Automation fails closed when:

- the execution state fingerprint no longer matches the scheduled job
- execution occurs outside the replay window without an explicit
  `delayed_but_safe` outcome
- duplicate suppression is not recorded explicitly
- operator override is required but not surfaced in the execution record

## Non-Goals

This profile does not claim:

- permissionless keeper networks as a trust root
- direct automatic settlement release without explicit operator controls
- hidden retry loops or state mutation outside signed Chio artifacts
- arbitrary off-chain scripting beyond the shipped bounded job families
