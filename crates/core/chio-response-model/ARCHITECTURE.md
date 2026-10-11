# chio-response-model

This crate owns the pure response evidence model shared by kernel admission and
the quarantine runtime. It gives both callers one definition of a response plan,
snapshot, effect mutation and authorized dispatch projection. The shared model
keeps the kernel independent of containment storage and scheduler orchestration.

## Boundary and public surface

`state` validates plan records and snapshot transitions, constructs mutation
candidates and encodes canonical response evidence. Its `projection` module
derives initial snapshots and normalizes the evidence used to authorize a
dispatch. `simulation` evaluates response plans against supplied snapshots
without applying their effects. Typed errors retain the reason a candidate is
invalid so each caller can select its own diagnostic and recovery behavior.

The crate receives all evidence and timestamps as input. It has no clock, store,
network client, executor or scheduler. Quarantine retains durable writes and
effect orchestration. The kernel retains admission and receipt authority. A
validated or simulated candidate has no independent authority to execute a
response, consume an approval or change durable state.

## Trust and dependency invariants

Canonical encoding, lifecycle validation and binding checks must fail closed on
invalid input. Shared response records come from `chio-security-types`; signing
vocabulary and canonical JSON helpers come from `chio-core-types`. The model
cannot depend directly or transitively on kernel, guard, platform, trust or
security engine crates. The dependency gate enforces that direction, including
reachability through an otherwise neutral helper crate.

## Verification

The security dependency self-test rejects direct and transitive violations and
requires this package to appear exactly once in Cargo metadata. The security
nextest lane includes the crate. Existing quarantine lifecycle, simulation and
kernel dispatch tests exercise the shared implementation through their owning
callers. Those behavioral suites remain necessary: passing a structural
dependency gate alone establishes no response execution or release readiness.
