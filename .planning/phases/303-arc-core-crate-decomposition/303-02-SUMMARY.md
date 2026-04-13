---
phase: 303-arc-core-crate-decomposition
plan: 02
subsystem: infra
tags:
  - rust
  - crates
  - arc-core
  - dependency-graph
  - compilation
requires:
  - "303-01"
provides:
  - extracted heavyweight ARC domain crates
  - explicit domain dependencies for wide consumers
  - `arc-core` compatibility facade over the extracted domains
affects:
  - phase-303-03
  - phase-304
  - phase-305
  - phase-306
tech-stack:
  added:
    - arc-appraisal
    - arc-autonomy
    - arc-credit
    - arc-federation
    - arc-governance
    - arc-listing
    - arc-market
    - arc-open-market
    - arc-underwriting
    - arc-web3
  patterns:
    - domain-crate extraction on top of `arc-core-types`
    - explicit consumer dependencies instead of umbrella-crate inheritance
    - compatibility-facade re-exports from `arc-core`
key-files:
  created:
    - crates/arc-appraisal/Cargo.toml
    - crates/arc-appraisal/src/lib.rs
    - crates/arc-credit/Cargo.toml
    - crates/arc-credit/src/lib.rs
    - crates/arc-market/Cargo.toml
    - crates/arc-market/src/lib.rs
    - crates/arc-web3/Cargo.toml
    - crates/arc-web3/src/lib.rs
    - .planning/phases/303-arc-core-crate-decomposition/303-02-SUMMARY.md
  modified:
    - Cargo.toml
    - crates/arc-core/Cargo.toml
    - crates/arc-core/src/lib.rs
    - crates/arc-core/src/appraisal.rs
    - crates/arc-core/src/autonomy.rs
    - crates/arc-core/src/credit.rs
    - crates/arc-core/src/federation.rs
    - crates/arc-core/src/governance.rs
    - crates/arc-core/src/listing.rs
    - crates/arc-core/src/market.rs
    - crates/arc-core/src/open_market.rs
    - crates/arc-core/src/underwriting.rs
    - crates/arc-core/src/web3.rs
    - crates/arc-kernel/Cargo.toml
    - crates/arc-cli/Cargo.toml
    - crates/arc-control-plane/Cargo.toml
    - crates/arc-settle/Cargo.toml
    - crates/arc-anchor/Cargo.toml
    - crates/arc-link/Cargo.toml
    - crates/arc-policy/Cargo.toml
    - crates/arc-web3-bindings/Cargo.toml
key-decisions:
  - "Extracted heavyweight business domains into standalone crates that depend on `arc-core-types` and each other directly."
  - "Wide consumers now declare the specific domain crates they use instead of inheriting those modules through `arc-core`."
  - "Kept `arc-core` as a compatibility facade so the remaining workspace migration can finish incrementally in `303-03`."
patterns-established:
  - "New heavyweight ARC protocol domains should ship as dedicated crates instead of growing `arc-core`."
  - "Wide runtime crates must declare direct dependencies on the domain crates they use."
requirements-completed:
  - DECOMP-02
  - DECOMP-03
duration: 8 min
completed: 2026-04-13
---

# Phase 303 Plan 02: Heavy Domain Extraction Summary

**ARC now has dedicated appraisal, listing, governance, underwriting, credit, market, federation, web3, and autonomy crates, with the major runtime consumers rewired to depend on those domains explicitly instead of inheriting them through `arc-core`**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-13T17:31:20Z
- **Completed:** 2026-04-13T17:39:39Z
- **Tasks:** 3
- **Files modified:** 41

## Accomplishments

- Added ten extracted domain crates and registered them as first-class workspace
  members on top of the new `arc-core-types` substrate.
- Rewired the wide consumers that actually use those business domains so their
  manifests declare explicit dependencies on appraisal, credit, federation,
  underwriting, web3, and related crates.
- Reduced the old `arc-core` heavy-domain modules to re-export shims so the
  historical `arc_core::*` surface still compiles while the final migration
  wave finishes.

## Task Commits

Each task landed as an atomic commit:

1. **Task 1: Extract the required heavy domains into explicit crates in
   dependency order** - `d1a7d99` (`feat`)
2. **Task 2: Rewire wide consumers to declare explicit domain dependencies** -
   `f355efe` (`feat`)
3. **Task 3: Keep `arc-core` as the honest facade over the extracted domains**
   - `4ca0390` (`refactor`)

## Files Created/Modified

- `crates/arc-appraisal/`, `crates/arc-listing/`, `crates/arc-governance/`,
  `crates/arc-open-market/`, `crates/arc-underwriting/`, `crates/arc-credit/`,
  `crates/arc-market/`, `crates/arc-federation/`, `crates/arc-web3/`, and
  `crates/arc-autonomy/` - new domain crates that now own the heavyweight ARC
  business artifacts.
- `Cargo.toml` - updated workspace membership for the extracted domains.
- `crates/arc-kernel/Cargo.toml`, `crates/arc-cli/Cargo.toml`,
  `crates/arc-control-plane/Cargo.toml`, `crates/arc-settle/Cargo.toml`,
  `crates/arc-anchor/Cargo.toml`, `crates/arc-link/Cargo.toml`,
  `crates/arc-policy/Cargo.toml`, and `crates/arc-web3-bindings/Cargo.toml` -
  direct dependency declarations for the domain crates those packages actually
  use.
- `crates/arc-core/Cargo.toml` and `crates/arc-core/src/*.rs` for the extracted
  domains - converted into the compatibility facade over the new crate graph.

## Decisions Made

- Used dedicated domain crates instead of feature-gating the heavy modules
  inside `arc-core`, because the dependency graph is now explicit and
  later dependency hygiene can target real crates.
- Left `arc-core` source-compatible by re-exporting the extracted domains from
  the historical module paths.
- Kept `arc-credentials` and `arc-did` unchanged because this extraction wave
  did not require new direct domain dependencies there.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The execution agent completed the implementation and verification but did not
  finish the summary and task-commit bookkeeping, so the final commit split and
  summary generation were completed in the main workspace after verification.

## User Setup Required

None.

## Next Phase Readiness

- `303-02` is complete and the heavyweight ARC business domains now have
  explicit crate boundaries.
- `303-03` can now finish the remaining direct-dependent migration, add the
  reproducible compile-time measurement script, and close the phase with the
  full compile and test matrix.
- No blocker is open for the final plan in phase 303.

---
*Phase: 303-arc-core-crate-decomposition*
*Completed: 2026-04-13*
