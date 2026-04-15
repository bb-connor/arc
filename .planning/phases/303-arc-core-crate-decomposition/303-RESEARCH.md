# Phase 303: arc-core Crate Decomposition - Research

**Researched:** 2026-04-13
**Domain:** Rust workspace architecture, crate decomposition, incremental
compilation, ARC core type boundaries
**Confidence:** HIGH

<phase_alignment>
## Phase Alignment

This phase is the first step of `v2.80 Core Decomposition and Async Kernel`.
It must reduce the `arc-core` gravity well without changing ARC behavior and
must leave phases `304-306` easier rather than harder:

- `304` depends on cleaner module and import boundaries
- `305` depends on kernel APIs no longer pulling the entire monolith through
  one crate
- `306` depends on feature-gating and dependency visibility being explicit at
  crate boundaries

The split therefore needs two properties at once:

1. **real compile isolation** for crates that only need capability, receipt,
   crypto, canonical JSON, or transport/session types
2. **compatibility-preserving migration** so downstream crates can move in
   controlled waves instead of a one-shot flag day

</phase_alignment>

<user_constraints>
## Locked Constraints

### Behavioral stability

- No ARC protocol or receipt semantics should change in this phase
- Existing crates must compile and existing tests must keep passing
- The split must be packaging and dependency work, not a hidden feature rewrite

### Honest decomposition

- `arc-core-types` must contain the small substrate every ARC crate truly needs
- heavyweight domain models must stop inflating unrelated compile paths
- `arc-core` may act as a temporary compatibility facade, but the end state
  must expose explicit domain crates rather than a renamed monolith

### Measurement

- The phase must produce a reproducible incremental-build comparison
- Compile-time improvement should be demonstrated on a crate that only needs
  shared substrate types, not on a wide consumer such as `arc-kernel`

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DECOMP-01 | `arc-core-types` contains capabilities, receipts, cryptographic signing, canonical JSON, and scope types | The existing `canonical`, `crypto`, `error`, large parts of `capability`, `receipt`, `message`, `manifest`, `session`, `hashing`, and `merkle` form the intended substrate, but `capability` and `receipt` need small decoupling work first. |
| DECOMP-02 | Domain types are extracted into separate crates depending on `arc-core-types` | The current monolith already clusters strongly by file. The heavy modules are natural crate seams once shared types stop importing domain-only enums. |
| DECOMP-03 | All dependent crates compile and tests pass against the decomposed structure | There are 26 workspace/example/test packages with direct or dev-dependencies on `arc-core`; the migration can be validated with a compile matrix plus targeted test runs on crates that consume extracted domains. |
| DECOMP-04 | Incremental rebuild for a shared-type change is measurably faster | Use a narrow dependent such as `arc-bindings-core`, `arc-manifest`, `arc-wall`, or `examples/hello-tool` and compare a touched shared-type file in monolithic `arc-core` versus `arc-core-types`. |

</phase_requirements>

## Summary

`arc-core` is a real monolith: `wc -l crates/arc-core/src/*.rs` shows 30,466
total lines, with the largest modules:

- `credit.rs` — 3,035 lines
- `appraisal.rs` — 2,746 lines
- `market.rs` — 2,707 lines
- `capability.rs` — 2,144 lines
- `autonomy.rs` — 2,010 lines
- `listing.rs` — 1,946 lines
- `web3.rs` — 1,934 lines
- `federation.rs` — 1,698 lines
- `open_market.rs` — 1,693 lines
- `session.rs` — 1,618 lines

The clean decomposition strategy is:

1. create `arc-core-types` as the minimal shared substrate
2. keep `arc-core` temporarily as a compatibility facade that re-exports new
   crates
3. extract domain crates in dependency order
4. move downstream crates off the facade onto explicit dependencies
5. prove compile improvement on narrow consumers

The key technical hazard is that the modules the roadmap calls “core” are not
fully core today:

- `capability.rs` imports `crate::appraisal::{derive_runtime_attestation_appraisal, AttestationVerifierFamily}`
- `receipt.rs` imports `crate::appraisal::AttestationVerifierFamily`
- `receipt.rs` imports `crate::web3::OracleConversionEvidence`

That means phase 303 cannot be only “move files to new crates.” It must first
stabilize a truly shared type boundary by either:

- lifting the tiny cross-cutting enums/structs into `arc-core-types`, or
- simplifying receipt/capability metadata so domain-specific payloads no longer
  live in the substrate crate

The lowest-risk path is a **facade-first split**:

- `arc-core-types` owns shared types and validation helpers
- if cycles remain, a thinner implementation-detail crate under
  `arc-core-types` may be required for primitives such as hashing, crypto,
  canonical JSON, aliases, and error types
- new domain crates own heavy business artifacts
- `arc-core` re-exports all of them during the migration so downstream code can
  be updated incrementally

## Current State

### 1. The monolith already contains obvious crate seams

The file layout in `crates/arc-core/src/` is already almost a crate map:

- **Shared substrate candidates**
  - `canonical.rs`
  - `crypto.rs`
  - `error.rs`
  - `hashing.rs`
  - `merkle.rs`
  - `manifest.rs`
  - `message.rs`
  - `session.rs`
  - most of `capability.rs`
  - most of `receipt.rs`
- **Heavy domain clusters**
  - `appraisal.rs`
  - `credit.rs`
  - `market.rs`
  - `federation.rs`
  - `governance.rs`
  - `listing.rs`
  - `underwriting.rs`
  - `autonomy.rs`
  - `web3.rs`
  - `open_market.rs`
  - `identity_network.rs`
  - `extension.rs`
  - `standards.rs`

This is a strong sign that the split should preserve existing conceptual file
boundaries rather than inventing new abstractions in phase 303.

### 2. Internal dependencies show the extraction order

A direct module scan shows these important dependencies:

- `credit.rs` depends on `appraisal`, `capability`, `crypto`, `receipt`,
  `underwriting`
- `market.rs` depends on `appraisal`, `capability`, `credit`, `crypto`,
  `receipt`, `underwriting`
- `web3.rs` depends on `capability`, `credit`, `crypto`, `hashing`,
  `merkle`, `receipt`
- `autonomy.rs` depends on `capability`, `market`, `receipt`, `web3`
- `federation.rs` depends on `capability`, `listing`, `open_market`, `receipt`
- `open_market.rs` depends on `capability`, `crypto`, `governance`, `listing`,
  `receipt`

Implication: domain crates cannot be extracted in arbitrary order. A low-risk
dependency order is:

1. `arc-core-types`
2. small support/domain crates with no heavy inbound dependencies
   (`arc-appraisal`, `arc-listing`, `arc-governance`, `arc-extension`,
   `arc-identity-network`, `arc-standards`)
3. `arc-underwriting`
4. `arc-credit`
5. `arc-market`
6. `arc-open-market`
7. `arc-federation`
8. `arc-web3`
9. `arc-autonomy`

### 3. Downstream usage confirms where compile wins will come from

A workspace scan of direct `arc_core::<module>` imports shows:

- `capability` is used by: `arc-a2a-adapter`, `arc-cli`, `arc-control-plane`,
  `arc-credentials`, `arc-guards`, `arc-kernel`, `arc-manifest`,
  `arc-mcp-edge`, `arc-mercury`, `arc-policy`, `arc-reputation`, `arc-settle`,
  `arc-store-sqlite`, `arc-wall`
- `receipt` is used by: `arc-a2a-adapter`, `arc-anchor`, `arc-cli`,
  `arc-control-plane`, `arc-credentials`, `arc-kernel`, `arc-mcp-edge`,
  `arc-mercury`, `arc-mercury-core`, `arc-reputation`, `arc-settle`,
  `arc-siem`, `arc-store-sqlite`, `arc-wall`
- `session` is used by: `arc-cli`, `arc-kernel`, `arc-mcp-adapter`,
  `arc-mcp-edge`, `arc-store-sqlite`
- `crypto` is used by: `arc-a2a-adapter`, `arc-anchor`, `arc-cli`,
  `arc-control-plane`, `arc-guards`, `arc-kernel`, `arc-manifest`,
  `arc-mcp-edge`, `arc-mercury`, `arc-mercury-core`, `arc-settle`,
  `arc-store-sqlite`, `arc-wall`

Heavy domain usage is much narrower:

- `credit` only shows up directly in `arc-kernel` and `arc-settle`
- `market` only shows up directly in `arc-kernel`
- `federation` only shows up directly in `arc-cli`
- `governance` only shows up directly in `arc-kernel`
- `web3` only shows up directly in `arc-anchor`, `arc-kernel`, `arc-link`,
  `arc-settle`

That means the compile-time win is real if the split is honest: many crates
currently rebuild domain modules they do not use only because everything lives
under `arc-core`.

### 4. `arc-core-types` needs one boundary-cleanup pass first

The roadmap’s desired substrate is slightly polluted today:

- `capability.rs` contains attestation trust policy logic tied to the appraisal
  domain
- `receipt.rs` embeds `OracleConversionEvidence`, which ties core receipts to
  the web3 domain
- `session.rs` depends on root aliases and shared exports from `lib.rs`, so the
  new crate root needs a stable export surface early

Recommended cleanup:

- move or re-home `AttestationVerifierFamily` and any similar tiny shared enums
  into `arc-core-types`
- keep full appraisal artifacts and evaluation logic in `arc-appraisal`
- move `OracleConversionEvidence` or a slim shared receipt-facing equivalent
  into the shared substrate only if receipts truly need the typed field;
  otherwise convert domain-specific receipt metadata to dedicated extensions or
  JSON wrappers
- preserve `arc-core` as a facade during migration so these small type moves do
  not force every dependent crate to update immediately

### 5. The direct dependency surface is bigger than the roadmap phrase implies

Parsing workspace/example/test manifests shows 26 direct or dev dependents on
`arc-core` today:

- 22 workspace crates under `crates/`
- `crates/arc-web3-bindings`
- `examples/hello-tool`
- `formal/diff-tests`
- `tests/e2e`

The requirement text says “all 25 dependent crates,” which is close but not
exact for the current repo. Phase 303 should treat the compile matrix as
26 packages unless the roadmap is updated.

## Recommended Cut

### Plan 01: create the shared substrate and compatibility facade

Goal:

- add `arc-core-types`
- if needed, add one thinner primitive support crate beneath it to break the
  current `capability` / `receipt` / `web3` dependency knot without violating
  the public requirement that `arc-core-types` be the shared crate consumers
  migrate to
- move or copy the shared modules into it
- clean the small appraisal/web3 leaks out of capability/receipt
- keep `arc-core` compiling as a thin re-export facade

Why first:

- it creates the stable seam every later extraction depends on
- it lets downstream crates begin migrating without a flag day
- it preserves phase 303 scope as decomposition, not feature work

### Plan 02: extract heavy domain crates in dependency order and rewire consumers

Goal:

- extract the named heavy modules into explicit domain crates
- update the narrow set of crates that truly depend on each domain
- keep `arc-core` as a transitional facade for any remaining imports

Recommended first extraction set:

- `arc-appraisal`
- `arc-listing`
- `arc-governance`
- `arc-underwriting`
- `arc-credit`
- `arc-market`
- `arc-federation`
- `arc-web3`
- `arc-autonomy`

This is the set that materially shrinks the shared compile path and satisfies
the roadmap’s named domain areas.

### Plan 03: remove accidental monolith coupling, prove compile/test stability, and measure rebuild improvement

Goal:

- update every direct dependent to use `arc-core-types` and explicit domain
  crates where appropriate
- run a compile/test matrix across all direct dependents
- add a reproducible measurement script or documented command sequence for the
  incremental rebuild comparison

The compile-time demonstration should target a narrow crate such as
`arc-bindings-core`, `arc-manifest`, `arc-wall`, or `examples/hello-tool`,
because those are the crates that should benefit most from not dragging in
`credit`, `market`, `web3`, and the rest.

## Validation Architecture

### Quick validation loop

Use quick feedback on the shared substrate and narrow dependents after every
meaningful refactor:

```bash
cargo check -p arc-core-types -p arc-core -p arc-bindings-core -p arc-manifest -p arc-wall
```

This catches broken re-exports, import churn, and shared-type regressions fast.

### Domain extraction loop

After each domain crate extraction, run the smallest directly affected compile
set, for example:

```bash
cargo check -p arc-kernel -p arc-cli -p arc-settle
```

Adjust the package list per extracted domain:

- `appraisal` / `federation` mainly affect `arc-cli`, `arc-control-plane`,
  `arc-policy`, `arc-kernel`
- `credit` / `market` / `web3` mainly affect `arc-kernel`, `arc-settle`,
  `arc-anchor`, `arc-link`

### Full phase verification

Before phase completion:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test -p arc-bindings-core -p arc-wall -p arc-store-sqlite -p arc-kernel -p arc-settle --tests
```

If the workspace build becomes too slow for every intermediate step, keep the
full `cargo check --workspace` as the wave/phase gate rather than the task gate.

### Incremental compile benchmark

Use one narrow consumer and compare monolith versus split with the same style
of source touch:

```bash
# Baseline on monolith branch / checkpoint
touch crates/arc-core/src/capability.rs
/usr/bin/time -p cargo check -p arc-bindings-core

# After split
touch crates/arc-core-types/src/capability.rs
/usr/bin/time -p cargo check -p arc-bindings-core
```

Prefer documenting the exact package, touched file, and warm-cache procedure in
`scripts/` or the phase summary so the comparison is reproducible.

## Risks and Mitigations

### Risk 1: receipt/capability still anchor domain types

If `receipt` and `capability` keep importing appraisal/web3-only payloads,
`arc-core-types` will still drag heavyweight crates.

Mitigation:

- clean these edges first
- keep only tiny cross-cutting enums/structs in the substrate
- move heavy evaluation/report artifacts into explicit domain crates

### Risk 2: circular domain crate graph

`market`, `credit`, `underwriting`, `autonomy`, `web3`, `federation`, and
`open_market` already reference each other.

Mitigation:

- extract in dependency order
- keep `arc-core` as a re-export facade during the transition
- do not require every consumer to switch off the facade in the same commit

### Risk 3: compile win is not visible if benchmark targets the wrong crate

`arc-kernel` will still depend on many domain crates even after the split, so
its compile time is a poor proof point.

Mitigation:

- benchmark a narrow consumer such as `arc-bindings-core`, `arc-manifest`,
  `arc-wall`, or `examples/hello-tool`

### Risk 4: phase 303 bleeds into phase 306 feature-gating work

It is tempting to do dependency cleanup and feature-gating at the same time as
crate extraction.

Mitigation:

- keep phase 303 focused on crate boundaries and dependency topology
- leave `serde_yaml`, duplicate `reqwest`, and web3 feature gating to phase 306

## Recommended Assumption

Phase 303 should treat `arc-core` as a **temporary compatibility facade** over
`arc-core-types` plus extracted domain crates. That is the safest way to ship a
real decomposition in one milestone phase without requiring a single giant
cross-workspace rewrite or weakening the promised compile win.
