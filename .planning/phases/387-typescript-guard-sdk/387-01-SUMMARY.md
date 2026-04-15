---
phase: 387-typescript-guard-sdk
plan: 01
subsystem: sdk
tags: [typescript, wasm, jco, componentize-js, esbuild, wasm-component-model, wit]

# Dependency graph
requires:
  - phase: 386-wit-guard-component-model
    provides: "WIT world definition (wit/arc-guard/world.wit) and Component Model support"
provides:
  - "@arc-protocol/guard-ts SDK package with WIT-generated TypeScript types"
  - "Example TypeScript guard (tool-gate) compiled to WASM Component Model binary"
  - "End-to-end build pipeline: jco types -> esbuild -> jco componentize"
affects: [387-02, typescript-guard-loading, guard-sdk-docs]

# Tech tracking
tech-stack:
  added: ["@bytecodealliance/jco ^1.17.6", "@bytecodealliance/componentize-js ^0.20.0", "esbuild ^0.28.0"]
  patterns: ["jco types for WIT-to-TypeScript .d.ts generation", "esbuild ESM bundling + jco componentize for TS-to-WASM compilation", "Tagged union Verdict type ({ tag: 'allow' } | { tag: 'deny', val: string })"]

key-files:
  created:
    - packages/sdk/arc-guard-ts/package.json
    - packages/sdk/arc-guard-ts/tsconfig.json
    - packages/sdk/arc-guard-ts/.gitignore
    - packages/sdk/arc-guard-ts/src/index.ts
    - packages/sdk/arc-guard-ts/examples/tool-gate/guard.ts
    - packages/sdk/arc-guard-ts/scripts/generate-types.sh
    - packages/sdk/arc-guard-ts/scripts/build-guard.sh
  modified: []

key-decisions:
  - "jco types (not jco guest-types) generates correct export-side .d.ts bindings for the guard world"
  - "WIT path is ../../../wit/arc-guard from packages/sdk/arc-guard-ts/ (3 levels deep)"
  - "tsconfig uses noEmit without rootDir/outDir to typecheck both src/ and examples/ together"
  - "Generated types use camelCase (toolName, serverId) and tagged union Verdict ({ tag: 'allow' } | { tag: 'deny', val: string })"
  - "dist/tool-gate.wasm is 11 MiB (includes SpiderMonkey engine); may need max_module_size adjustment in Plan 02"

patterns-established:
  - "TypeScript guard pattern: import types from jco-generated .d.ts, export evaluate(request: GuardRequest): Verdict"
  - "Build pipeline: npm run generate-types -> esbuild bundle -> jco componentize --disable all"
  - "Component Model binary detection: magic bytes 0x00 0x61 0x73 0x6d followed by layer byte 0x0d"

requirements-completed: [TSDK-01, TSDK-02, TSDK-03]

# Metrics
duration: 3min
completed: 2026-04-14
---

# Phase 387 Plan 01: TypeScript Guard SDK Summary

**WIT-generated TypeScript SDK with jco types, example tool-gate guard, and esbuild+componentize-js WASM build pipeline**

## Performance

- **Duration:** 3 min
- **Started:** 2026-04-15T02:58:05Z
- **Completed:** 2026-04-15T03:01:11Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Scaffolded @arc-protocol/guard-ts SDK package with jco, componentize-js, esbuild, typescript deps
- Generated TypeScript .d.ts types from wit/arc-guard/world.wit via jco -- GuardRequest with all 10 fields, Verdict tagged union
- Built example TypeScript guard (tool-gate) that mirrors Rust deny-list behavior, compiles to 11 MiB WASM Component Model binary
- End-to-end pipeline works in 2 commands: npm install + npm run build:example

## Task Commits

Each task was committed atomically:

1. **Task 1: Scaffold SDK package and generate types from WIT** - `8264ff0` (feat)
2. **Task 2: Create example guard and build pipeline** - `f9602e0` (feat)

## Files Created/Modified
- `packages/sdk/arc-guard-ts/package.json` - SDK package with jco, componentize-js, esbuild, typescript
- `packages/sdk/arc-guard-ts/tsconfig.json` - TypeScript config for typecheck (noEmit, strict, includes examples)
- `packages/sdk/arc-guard-ts/.gitignore` - Ignores node_modules, dist, src/types (generated)
- `packages/sdk/arc-guard-ts/src/index.ts` - Re-exports generated GuardRequest, Verdict, VerdictAllow, VerdictDeny
- `packages/sdk/arc-guard-ts/examples/tool-gate/guard.ts` - Example guard with deny list (dangerous_tool, rm_rf, drop_database)
- `packages/sdk/arc-guard-ts/scripts/generate-types.sh` - Standalone WIT type generation script
- `packages/sdk/arc-guard-ts/scripts/build-guard.sh` - Full build pipeline script
- `packages/sdk/arc-guard-ts/package-lock.json` - Lock file for reproducible installs

## Decisions Made
- **jco types over jco guest-types**: `jco types --world-name guard` correctly generates export-side .d.ts bindings; no need for guest-types subcommand
- **WIT path correction**: Plan specified `../../wit/arc-guard` but actual path from `packages/sdk/arc-guard-ts/` is `../../../wit/arc-guard` (3 levels deep)
- **tsconfig without rootDir**: Removed rootDir/outDir since tsconfig is noEmit-only; allows typechecking both src/ and examples/ without rootDir conflicts
- **11 MiB WASM size**: Expected with SpiderMonkey engine included by componentize-js; Plan 02 may need to adjust ComponentBackend max_module_size

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed WIT relative path from 2 to 3 levels**
- **Found during:** Task 1 (generate-types)
- **Issue:** Plan specified `../../wit/arc-guard` but `packages/sdk/arc-guard-ts/` is 3 directories deep from project root
- **Fix:** Changed all WIT paths to `../../../wit/arc-guard` in package.json and generate-types.sh
- **Files modified:** packages/sdk/arc-guard-ts/package.json, packages/sdk/arc-guard-ts/scripts/generate-types.sh
- **Verification:** npm run generate-types succeeds, produces correct .d.ts files
- **Committed in:** 8264ff0 (Task 1 commit)

**2. [Rule 1 - Bug] Fixed tsconfig rootDir conflict with examples include**
- **Found during:** Task 2 (typecheck with example)
- **Issue:** tsconfig had rootDir: ./src but include: ["examples/**/*.ts"], causing TS6059 error
- **Fix:** Removed outDir and rootDir since tsconfig is noEmit-only for typechecking
- **Files modified:** packages/sdk/arc-guard-ts/tsconfig.json
- **Verification:** npm run typecheck passes with both src/ and examples/ files
- **Committed in:** f9602e0 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both fixes were necessary for correct path resolution and typecheck. No scope creep.

## Issues Encountered
None beyond the auto-fixed deviations above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- SDK package ready; Plan 02 can integrate WASM loading into the ARC host
- Note: 11 MiB WASM size may require ComponentBackend max_module_size adjustment
- Generated types can be used by any TypeScript guard author via import from @arc-protocol/guard-ts

---
*Phase: 387-typescript-guard-sdk*
*Completed: 2026-04-14*
