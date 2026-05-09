# RESOLVE_DEFERRED

Threads requiring manual triage (claim verification failed or thread node not found).

- A row 7 | PR #128 | comment 3144490367 | REJECTED: TRIAGE claims golden_byte_equivalence.rs root hash canonicalization rewritten; live file still uses serde_json::to_vec on json! values without canonicalize at line 198-200 (sample-checked).
- A row 27 | PR #15 | comment 3142804095 | REJECTED: TRIAGE claims COVERAGE.md 'Current' column was rewritten; live file still has the column at line 218 with the same stale receipt=8, capability=10 values flagged by the original comment (sample-checked).
