# chio-workflow-preflight architecture

## Responsibility and boundary

`evaluate_workflow_preflight` accepts `WorkflowPreflightPlan` and returns
`WorkflowPreflightReport` or a shape error. The input includes a parent
task, nonempty child task collection, requested scopes, route support,
approval statuses, registry support, a budget pool, revocation metadata, and
planning artifacts.

The output records accepted/rejected planning checks and uses
`evidence_class = planning`. `live_authority_claims` is always empty. The
crate performs no tool execution, issuance, signature authentication, budget
reservation, or access to live approval/revocation state.

## Structure

`types.rs` defines strict serde types, schema constants, errors, verdicts,
and check records. `scope.rs` checks child containment and aggregate parent
budget. `validation.rs` validates shape and collects route, approval,
registry, budget, revocation, and planning-artifact failures. `lib.rs`
composes those checks and constructs the report. `chio-workflow` re-exports
this library for skill users.

## Data and control flow

Malformed schema, missing identifiers, empty required scopes, and malformed
revocation root hashes return `WorkflowPreflightError`. For a well-shaped
plan, the evaluator accumulates scope and gate failures into
`rejected_checks`. Any check produces `Rejected`; a plan without checks
receives two planning claims.

Child action/resource/route/approval/schema entries must appear in the
parent sets unless a parent set contains the literal wildcard `*`. Child
parent IDs and currencies must match. Individual and checked aggregate
budgets must stay within the parent envelope and pool. Arithmetic overflow
is a rejection.

## Trust and invariants

Route references requested by children require supplied support entries set
to true; approval references require status `approved`. Conflicting
duplicate statuses/support entries are rejected. Required schemas must
appear in supplied registry support. Revocation status must equal `fresh`,
while its root is checked for SHA-256 shape.

Freshness is a declared status: no time source, trusted root, or revocation
oracle is consulted. A planning artifact with nonempty `satisfies_claims` is
rejected regardless of its artifact class. Accepted planning output must be
followed by independent live authority checks at execution.

## Dependencies

`serde`/`serde_json` decode and encode the planning/report vocabulary.
`thiserror` defines unsupported-schema and invalid-plan errors. The library
has no kernel, cryptographic, network, clock, or persistence dependency. It
declares no Cargo features.

## Verification

`tests/preflight.rs` loads proof-room fixtures and covers accepted child
scope, broader scope, aggregate budget excess, blank scope entries, missing
routes/approvals/schemas, stale declared revocation, and live-authority
overreach. Run `cargo test -p chio-workflow-preflight`. The README embeds
`valid-child-scope/preflight-plan.json` from the repository and checks its
planning verdict and empty live-authority list.
