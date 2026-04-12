# Phase 219 Context

ARC's generic SQLite receipt store still depended on `arc-mercury-core` and
maintained a Mercury-only receipt index even after the generic query surface
was cleaned up. This phase removes that store-level product coupling and keeps
only generic receipt persistence behavior in ARC storage.

Non-goals:
- do not introduce a replacement Mercury-specific store path inside ARC
- do not weaken generic receipt storage, pagination, or attribution behavior
- do not change Mercury app-owned package or metadata contracts here
