---
phase: 303-arc-core-crate-decomposition
plan: 01
subsystem: infra
tags:
  - rust
  - crates
  - arc-core
  - compilation
requires: []
provides:
  - shared `arc-core-types` substrate crate
  - decoupled shared capability and receipt surfaces
  - `arc-core` compatibility facade over the shared substrate
affects:
  - phase-303-02
  - phase-303-03
  - phase-304
  - phase-306
tech-stack:
  added:
    - arc-core-types
  patterns:
    - compatibility-facade crate split
    - shared-type extraction before domain-crate extraction
key-files:
  created:
    - crates/arc-core-types/Cargo.toml
    - crates/arc-core-types/src/lib.rs
    - crates/arc-core-types/src/canonical.rs
    - crates/arc-core-types/src/capability.rs
    - crates/arc-core-types/src/crypto.rs
    - crates/arc-core-types/src/error.rs
    - crates/arc-core-types/src/hashing.rs
    - crates/arc-core-types/src/manifest.rs
    - crates/arc-core-types/src/merkle.rs
    - crates/arc-core-types/src/message.rs
    - crates/arc-core-types/src/oracle.rs
    - crates/arc-core-types/src/receipt.rs
    - crates/arc-core-types/src/runtime_attestation.rs
    - crates/arc-core-types/src/session.rs
    - .planning/phases/303-arc-core-crate-decomposition/303-01-SUMMARY.md
  modified:
    - Cargo.toml
    - Cargo.lock
    - crates/arc-core/Cargo.toml
    - crates/arc-core/src/lib.rs
    - crates/arc-core/src/appraisal.rs
    - crates/arc-core/src/canonical.rs
    - crates/arc-core/src/capability.rs
    - crates/arc-core/src/crypto.rs
    - crates/arc-core/src/error.rs
    - crates/arc-core/src/hashing.rs
    - crates/arc-core/src/manifest.rs
    - crates/arc-core/src/merkle.rs
    - crates/arc-core/src/message.rs
    - crates/arc-core/src/receipt.rs
    - crates/arc-core/src/session.rs
    - crates/arc-core/src/web3.rs
key-decisions:
  - "Used `arc-core-types` as the new public shared substrate instead of introducing a user-facing multi-crate layering immediately."
  - "Moved lightweight runtime-attestation and oracle metadata into the shared substrate so `capability` and `receipt` no longer depend on full appraisal/web3 domains."
  - "Kept `arc-core` as a compatibility facade so downstream crates can migrate incrementally in later plans."
patterns-established:
  - "Future domain extractions should move heavy business modules into dedicated crates while keeping `arc-core` as a transitional re-export shell."
  - "Shared ARC protocol surfaces must not depend on heavyweight domain modules; move only the lightweight cross-cutting types into the substrate."
requirements-completed:
  - DECOMP-01
duration: 4 min
completed: 2026-04-13
---

# Phase 303: arc-core Crate Decomposition Summary

**ARC now has a dedicated `arc-core-types` substrate crate, with shared capability, receipt, session, manifest, crypto, canonical JSON, hashing, and merkle code extracted out of the old monolith and re-exposed through an `arc-core` compatibility facade**

## Performance

- **Duration:** 4 min
- **Started:** 2026-04-13T17:11:19Z
- **Completed:** 2026-04-13T17:15:05Z
- **Tasks:** 3
- **Files modified:** 18

## Accomplishments

- Added `crates/arc-core-types` and populated it with the shared ARC substrate
  modules that narrow consumers should depend on.
- Decoupled the shared `capability` and `receipt` surfaces from full
  appraisal/web3 domain ownership by introducing shared runtime-attestation and
  oracle metadata modules in the extracted crate.
- Turned `arc-core` into the compatibility shell over `arc-core-types` and
  refreshed the lockfile for the new workspace topology.

## Task Commits

Each task landed as an atomic commit:

1. **Task 1: Create `arc-core-types` and move the shared substrate into it** -
   `bfa5fb9` (`feat`)
2. **Task 2: Remove the appraisal and web3 leaks from the shared capability and
   receipt surfaces** - `32dabfe` (`fix`)
3. **Task 3: Turn `arc-core` into a compatibility facade over `arc-core-types`**
   - `beb94a0` (`refactor`)
4. **Task 3 follow-up: Refresh lockfile for the new shared substrate split** -
   `55b9122` (`chore`)

## Files Created/Modified

- `crates/arc-core-types/` - new shared ARC substrate crate
- `crates/arc-core/src/lib.rs` - compatibility-facade crate root over the
  extracted substrate
- `crates/arc-core/src/capability.rs` and `crates/arc-core/src/receipt.rs` -
  reduced to re-export shells over `arc-core-types`
- `crates/arc-core/src/appraisal.rs` and `crates/arc-core/src/web3.rs` -
  aligned to use the shared attestation/oracle metadata types
- `Cargo.toml` and `Cargo.lock` - workspace membership and dependency graph
  updated for `arc-core-types`

## Decisions Made

- `arc-core-types` is the new public shared substrate crate, while `arc-core`
  remains the compatibility shell during the rest of phase 303.
- Lightweight cross-cutting metadata stays in the substrate; heavyweight
  appraisal and web3 artifacts stay outside it.
- The lockfile change is part of the plan-01 surface because downstream compile
  validation depends on the new crate graph being recorded explicitly.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Shared receipt and capability surfaces still depended on full domain modules**
- **Found during:** Task 2
- **Issue:** `capability` and `receipt` still imported appraisal- and web3-only
  types, which would have made `arc-core-types` a renamed monolith rather than
  a real shared substrate.
- **Fix:** Introduced shared runtime-attestation and oracle metadata modules in
  `arc-core-types` and rewired `arc-core` domain modules to use them.
- **Files modified:** `crates/arc-core-types/src/runtime_attestation.rs`,
  `crates/arc-core-types/src/oracle.rs`, `crates/arc-core/src/appraisal.rs`,
  `crates/arc-core/src/web3.rs`
- **Verification:** `cargo check -p arc-core-types -p arc-core -p arc-bindings-core -p arc-manifest -p arc-wall`
- **Committed in:** `32dabfe`

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary to make DECOMP-01 honest. No scope creep beyond
the shared-substrate boundary cleanup already implied by the research.

## Issues Encountered

- The executor stalled after landing the code commits and did not write the
  plan summary, so summary/bookkeeping completion was finished manually after
  the compile gate passed.

## User Setup Required

None.

## Next Phase Readiness

- `303-01` is complete and the shared substrate is now in place.
- `303-02` can begin the heavyweight domain-crate extraction on top of the new
  `arc-core-types` boundary.
- The compile-time proof (`DECOMP-04`) still remains for `303-03`; no benchmark
  evidence exists yet.

---
*Phase: 303-arc-core-crate-decomposition*
*Completed: 2026-04-13*
