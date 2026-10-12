# chio-workflow architecture

## Responsibility and boundary

`SkillManifest` owns a declared sequence of `SkillStep` values and optional
workflow budgets/time limits. `SkillGrant` names an authorized skill/version
and permitted server/tool pairs. `WorkflowAuthority` tracks executions and
produces `WorkflowReceipt`. The caller supplies authenticated grants,
capability IDs, agent/session bindings, actual tool results, costs, and
underlying receipt IDs.

The authority coordinates metadata and records; it has no tool invocation
API. Tool authorization at the kernel boundary and independent verification
of reported outputs remain consumer responsibilities. `preflight` re-exports
the separate planning verifier.

## Structure

`manifest.rs` defines manifests, steps, and `IoContract`, including
`validate_io_contracts` for required/produced field relationships.
`grant.rs` defines membership and strict-order checks. `authority.rs` owns
lifecycle state, execution reservations, budgets, time limits, and final
outcome selection. `receipt.rs` signs workflow bodies and supports detached
vendor signatures and required vendor-key matching.

## Data and control flow

`begin` compares skill identity/version, checks all declared tool pairs, and
reserves capacity under the capability ID when `max_executions` is set.
Grant budget/duration options take precedence over manifest options. IDs
combine current Unix seconds, an authority-local counter, and agent
identity.

`validate_step` checks membership and index order against the number of
successful records. `record_step` updates supplied costs and appends a
record before returning budget/time violations. Currency mismatches and
limits mark the execution inactive. Finalization consumes execution state
and signs a receipt; successful signing updates reserved execution counts.

## Trust and invariants

`begin` does not call `validate_io_contracts`, authenticate the grant, or
validate its schema. `validate_step` does not reserve estimated cost; budget
checks occur when a result is recorded. `record_step` does not repeat
authorization/order validation, so callers must use the lifecycle in order.

Finalization has no retained manifest step count. An execution with no
failure records or terminal error can become `Completed` even when the
declared sequence is incomplete. Limited counters are process-local and a
dropped execution leaves its reservation in flight. Unix wall time, with
zero fallback on clock failure, governs elapsed time. Receipt signature
checks use the embedded key; consumers pin that identity separately.

## Dependencies

`chio-core` supplies monetary amounts, cryptographic keys, and canonical
receipt signing. `chio-workflow-preflight` supplies planning evaluation
re-exports. `serde`/`serde_json` serialize artifacts, `thiserror` defines
typed lifecycle failures, and `tracing` emits execution start/finalization
events.

## Verification

Unit tests cover membership/order, I/O field dependencies, canonical receipt
signatures, vendor signer requirements, execution limits, budget currency
failures, timeouts, and recording over-budget steps. `tests/preflight.rs`
exercises the planning re-export. Run `cargo test -p chio-workflow`. The
README uses a synthetic result, default features, and local key material; it
opens no service and verifies the generated signature.
