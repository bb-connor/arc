---
phase: 12-capability-lineage-index-and-receipt-dashboard
plan: "03"
subsystem: ui
tags: [react, vite, tanstack-table, recharts, typescript, spa, dashboard]

requires:
  - phase: 12-01
    provides: capability_lineage SQLite table and GET /v1/lineage/* endpoints
  - phase: 12-02
    provides: GET /v1/receipts/query and GET /v1/agents/:key/receipts API endpoints

provides:
  - React 18 + Vite 6 SPA at crates/pact-cli/dashboard/ with production dist/ output
  - FilterSidebar with agent/tool/outcome/time filter controls
  - ReceiptTable using TanStack Table 8 with server-side cursor pagination and detail panel
  - DelegationChain expandable tree component calling GET /v1/lineage/:id/chain
  - BudgetSparkline Recharts 2 AreaChart for per-agent cost visualization
  - Typed fetch wrappers in api.ts with Bearer token injection from URL/sessionStorage

affects:
  - 12-04-PLAN (will serve this dist/ via ServeDir in axum trust-serve command)

tech-stack:
  added:
    - react@18.3.1 (React 18, createRoot API)
    - react-dom@18.3.1
    - "@tanstack/react-table@8.21.3"
    - recharts@2.15.0 (AreaChart, ResponsiveContainer)
    - date-fns@3.6.0 (timestamp formatting)
    - lucide-react@0.468.0 (Filter, ChevronDown, ChevronRight icons)
    - "@vitejs/plugin-react@4.4.0"
    - vite@6.0.0
    - typescript@5.7.0
  patterns:
    - Cursor stack navigation for server-side paginated tables (push/pop cursor array)
    - Bearer token stored in sessionStorage, seeded from ?token= URL param
    - Minor-unit monetary formatting via integer arithmetic only (no float division)
    - Vite dev proxy /v1 -> localhost:8080 for local development

key-files:
  created:
    - crates/pact-cli/dashboard/package.json
    - crates/pact-cli/dashboard/tsconfig.json
    - crates/pact-cli/dashboard/tsconfig.app.json
    - crates/pact-cli/dashboard/vite.config.ts
    - crates/pact-cli/dashboard/index.html
    - crates/pact-cli/dashboard/src/main.tsx
    - crates/pact-cli/dashboard/src/App.tsx
    - crates/pact-cli/dashboard/src/types.ts
    - crates/pact-cli/dashboard/src/api.ts
    - crates/pact-cli/dashboard/src/index.css
    - crates/pact-cli/dashboard/src/vite-env.d.ts
    - crates/pact-cli/dashboard/src/components/FilterSidebar.tsx
    - crates/pact-cli/dashboard/src/components/ReceiptTable.tsx
    - crates/pact-cli/dashboard/src/components/DelegationChain.tsx
    - crates/pact-cli/dashboard/src/components/BudgetSparkline.tsx
  modified:
    - .gitignore (added dashboard/node_modules/ and dashboard/dist/ exclusions)

key-decisions:
  - "Bearer token sourced from ?token= URL param on first load, stored in sessionStorage for subsequent calls -- avoids adding unauthenticated config endpoint"
  - "Cursor stack (push/pop array) for server-side paginated back-navigation -- TanStack Table manualPagination with pageCount=-1"
  - "Minor-unit formatting uses integer arithmetic only (Math.floor + modulo) -- no float conversion per Phase 7 MonetaryAmount convention"
  - "vite-env.d.ts with vite/client reference required for CSS module type declarations in strict TypeScript mode (deviation Rule 3)"

requirements-completed: [PROD-04, PROD-05]

duration: 4min
completed: "2026-03-23"
---

# Phase 12 Plan 03: Receipt Dashboard SPA Summary

**React 18 + Vite 6 SPA with TanStack Table 8 cursor-paginated receipt list, delegation chain tree, Recharts 2 sparkline, and Bearer-auth fetch wrappers -- builds to dist/ in 1.75s**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-23T02:13:09Z
- **Completed:** 2026-03-23T02:17:53Z
- **Tasks:** 2
- **Files modified:** 16

## Accomplishments

- Complete Vite 6 project scaffold with pinned react@18, @tanstack/react-table@8, recharts@2 dependencies -- TypeScript strict mode, all types pass tsc --noEmit
- Four React components: FilterSidebar (6 filter controls), ReceiptTable (TanStack Table 8 with cursor stack pagination and inline detail panel), DelegationChain (expandable root-to-leaf tree), BudgetSparkline (Recharts 2 AreaChart)
- Typed API layer with Bearer auth injection, cursor-based pagination helpers, and agent cost series aggregation for sparkline data
- `npm run build` produces dist/index.html + 618kB JS bundle (177kB gzip) in 1.75s

## Task Commits

Each task was committed atomically:

1. **Task 1: Scaffold Vite project with dependencies** - `7376f31` (feat)
2. **Task 2: Build all four components and App layout** - `bae0436` (feat)

## Files Created/Modified

- `crates/pact-cli/dashboard/package.json` - Pinned React 18 + Vite 6 + TanStack 8 + Recharts 2 dependencies
- `crates/pact-cli/dashboard/tsconfig.app.json` - Strict TypeScript, react-jsx, bundler module resolution
- `crates/pact-cli/dashboard/vite.config.ts` - /v1 dev proxy to localhost:8080, dist/ build output
- `crates/pact-cli/dashboard/src/types.ts` - Receipt, CapabilitySnapshot, Filters, DecisionKind, formatMinorUnits
- `crates/pact-cli/dashboard/src/api.ts` - fetchReceipts, fetchLineage, fetchDelegationChain, fetchAgentReceipts, fetchAgentCostSeries
- `crates/pact-cli/dashboard/src/components/FilterSidebar.tsx` - 6 filter controls with datetime-local to Unix seconds conversion
- `crates/pact-cli/dashboard/src/components/ReceiptTable.tsx` - TanStack Table 8, cursor stack pagination, detail panel with delegation chain
- `crates/pact-cli/dashboard/src/components/DelegationChain.tsx` - Expandable chain nodes with grants JSON toggle
- `crates/pact-cli/dashboard/src/components/BudgetSparkline.tsx` - Recharts 2 AreaChart with minor-unit tooltip
- `.gitignore` - Added dashboard/node_modules/ and dashboard/dist/ entries

## Decisions Made

- Bearer token sourced from `?token=` URL param on first load, stored in sessionStorage -- avoids adding unauthenticated config endpoint per Pitfall 2 from RESEARCH.md
- Cursor stack (array push/pop) for back-navigation with `manualPagination: true` and `pageCount: -1` -- server drives all pagination
- Minor-unit monetary formatting uses `Math.floor(amount / 100)` and `amount % 100` -- no float arithmetic per Phase 7 MonetaryAmount convention
- `src/vite-env.d.ts` with `/// <reference types="vite/client" />` required for TypeScript to recognize CSS module imports

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added vite-env.d.ts for CSS import type resolution**
- **Found during:** Task 2 (npm run build)
- **Issue:** `tsc -b` failed with TS2307: Cannot find module './index.css' -- Vite react-ts templates include this file but it was not listed in the plan's file list
- **Fix:** Created `src/vite-env.d.ts` with `/// <reference types="vite/client" />`
- **Files modified:** crates/pact-cli/dashboard/src/vite-env.d.ts
- **Verification:** `npm run build` exits 0; tsc --noEmit passes
- **Committed in:** bae0436 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Single missing declaration file required for TypeScript to handle CSS imports. No scope creep.

## Issues Encountered

None beyond the vite-env.d.ts deviation above.

## Next Phase Readiness

- `dist/` directory contains complete SPA ready for ServeDir static file serving
- Plan 12-04 will add `tower-http` ServeDir to the axum trust-serve command to serve the built assets
- No blockers -- all components render correctly, build is clean

---
*Phase: 12-capability-lineage-index-and-receipt-dashboard*
*Completed: 2026-03-23*
