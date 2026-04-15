---
phase: 388-python-and-go-guard-sdks
plan: 01
subsystem: sdk
tags: [python, wasm, component-model, componentize-py, guard, wit]

requires:
  - phase: 386-wit-component-model-guard-runtime
    provides: WIT contract (wit/arc-guard/world.wit) and ComponentBackend
  - phase: 387-typescript-guard-sdk
    provides: SDK pattern and directory structure convention

provides:
  - Python guard SDK package at packages/sdk/arc-guard-py/
  - Typed dataclasses matching all 10 WIT guard-request fields
  - Example tool-gate guard compiled to WASM Component Model binary
  - componentize-py build pipeline with --stub-wasi for zero-import guards

affects: [388-02, 388-03, arc-wasm-guards, arc-kernel]

tech-stack:
  added: [componentize-py 0.22.1, setuptools]
  patterns: [componentize-py --world-module guard, --stub-wasi compilation, app.py entrypoint convention]

key-files:
  created:
    - packages/sdk/arc-guard-py/pyproject.toml
    - packages/sdk/arc-guard-py/src/arc_guard/__init__.py
    - packages/sdk/arc-guard-py/src/arc_guard/types.py
    - packages/sdk/arc-guard-py/examples/tool-gate/app.py
    - packages/sdk/arc-guard-py/scripts/build-guard.sh
    - packages/sdk/arc-guard-py/scripts/generate-types.sh
    - packages/sdk/arc-guard-py/.gitignore
  modified: []

key-decisions:
  - "--world-module guard used to name generated bindings module 'guard' instead of default 'wit_world' for ergonomic imports"
  - "Example entrypoint renamed from guard.py to app.py because componentize-py APP_NAME must not clash with world module name"
  - "Guard class implements Protocol from generated bindings rather than standalone function export (componentize-py convention)"
  - "componentize-py 0.22.1 generates Guard protocol class (not Evaluate) for the guard world"

patterns-established:
  - "Python guard entrypoint: app.py with class Guard(BaseGuard) implementing evaluate()"
  - "Build pipeline: componentize-py with -d WIT_PATH -w guard --world-module guard --stub-wasi"
  - "Generated bindings in guard/ directory, gitignored alongside componentize_py runtime files"

requirements-completed: [PYDK-01, PYDK-02, PYDK-03]

duration: 4min
completed: 2026-04-15
---

# Phase 388 Plan 01: Python Guard SDK Summary

**Python guard SDK with typed dataclasses from WIT contract, example tool-gate guard, and componentize-py pipeline producing an 18 MiB WASM Component Model binary**

## Performance

- **Duration:** 4 min
- **Started:** 2026-04-15T03:28:55Z
- **Completed:** 2026-04-15T03:32:58Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Python SDK package with GuardRequest dataclass matching all 10 WIT guard-request fields
- Example tool-gate guard with deny list compiles to 17.6 MiB Component Model binary via componentize-py
- Build pipeline runs end-to-end in 2 commands (install componentize-py + run build script)
- WASM binary confirmed as Component Model format (version 0x0d) with --stub-wasi for zero host imports

## Task Commits

Each task was committed atomically:

1. **Task 1: Scaffold Python SDK package with typed dataclasses and example guard** - `97a525d` (feat)
2. **Task 2: Create build scripts and compile example guard to WASM** - `54ea8c9` (feat)

## Files Created/Modified

- `packages/sdk/arc-guard-py/pyproject.toml` - Package metadata, setuptools backend, no runtime deps
- `packages/sdk/arc-guard-py/src/arc_guard/__init__.py` - Re-exports GuardRequest, VerdictAllow, VerdictDeny, Verdict
- `packages/sdk/arc-guard-py/src/arc_guard/types.py` - Ergonomic dataclasses mirroring WIT guard-request and verdict types
- `packages/sdk/arc-guard-py/examples/tool-gate/app.py` - Example guard implementing evaluate with deny list
- `packages/sdk/arc-guard-py/scripts/build-guard.sh` - Full pipeline: generate bindings + componentize to WASM
- `packages/sdk/arc-guard-py/scripts/generate-types.sh` - Generate Python bindings from WIT
- `packages/sdk/arc-guard-py/.gitignore` - Covers dist/, guard/, runtime files, Python artifacts

## Decisions Made

- Used `--world-module guard` to name generated bindings module `guard` for ergonomic `from guard import Guard` imports
- Renamed example from `guard.py` to `app.py` because componentize-py requires APP_NAME to not clash with the world module name (`guard`)
- componentize-py 0.22.1 generates a `Guard` protocol class (not `Evaluate`) -- the generated API was discovered by running bindings generation first
- Added componentize_py runtime files (componentize_py_async_support/, poll_loop.py, etc.) to .gitignore since they are generated at build time

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed module name clash between app and world module**
- **Found during:** Task 2 (build script compilation)
- **Issue:** componentize-py APP_NAME (`guard`) clashed with `--world-module guard` causing `ModuleNotFoundError`
- **Fix:** Renamed `examples/tool-gate/guard.py` to `examples/tool-gate/app.py`, used `-p examples/tool-gate app` in build command
- **Files modified:** examples/tool-gate/app.py (renamed), scripts/build-guard.sh
- **Verification:** Build succeeds, 17.6 MiB Component Model binary produced
- **Committed in:** 54ea8c9 (Task 2 commit)

**2. [Rule 3 - Blocking] Updated import paths to match generated bindings**
- **Found during:** Task 2 (bindings generation)
- **Issue:** Plan guessed `from guard import Evaluate`; actual generated class is `from guard import Guard`
- **Fix:** Updated imports in app.py to `from guard import Guard as BaseGuard` and `from guard.imports.types import ...`
- **Files modified:** examples/tool-gate/app.py
- **Verification:** Compilation succeeds with correct imports
- **Committed in:** 54ea8c9 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (both blocking issues)
**Impact on plan:** Both fixes were necessary for compilation. The plan explicitly anticipated import path discovery during Task 2. No scope creep.

## Issues Encountered

- componentize-py installed via pip to Python 3.13 at `/Users/connor/.proto/tools/python/3.13.0/bin/componentize-py` but not on default PATH; build scripts use bare `componentize-py` command which requires the correct Python bin directory in PATH

## User Setup Required

None - no external service configuration required. `pip install componentize-py` is the only prerequisite.

## Next Phase Readiness

- Python SDK package is complete and ready for host integration tests (388-02)
- ComponentBackend max_module_size may need adjustment (17.6 MiB exceeds default 10 MiB, same as TS SDK)
- Go guard SDK (388-03) can proceed independently

## Self-Check: PASSED

All 8 created files verified present on disk. Both task commits (97a525d, 54ea8c9) verified in git log. dist/tool-gate.wasm confirmed as Component Model binary (version 0x0d, 17.6 MiB).

---
*Phase: 388-python-and-go-guard-sdks*
*Completed: 2026-04-15*
