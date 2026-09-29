# SQLite performance and retention evidence

Source base a3669c03d1; production measurement/review candidate 8aa3cf1785;
diagnostic completion repair b9d6af6fb0. See the parent execution report for
completion boundaries. Historical and large raw logs are gzip-compressed;
manifest.json pins both original and archived bytes. Compiled executables,
shared libraries and Cargo dependency-message streams are omitted. Runners are
historical commands with machine-local paths, not installed product tooling.

- comparison.json, before-/after-/change-*.json and bench-*.log: all eight paired
  measurements, exact scopes and preserved preliminary fixture failure.
- cache-red/green and task-1-tests.log: real compilation/read counts before and
  after caching, plus final regression verification.
- budget-tests.log: 142 passes and 2 fixture failures; checked-accounting-final
  logs/results: complete five-test group passes after private fixture repair.
- focused-test-results.json and owning logs: fence, replay, rollback and recovery
  qualification; isolated child result appears inside the serving-owner log.
- issue-1045.json, historical-msrv-job.log.gz and its readable excerpt: original
  canceled job and its workload configuration, not a new historical reproduction.
- retention-original-scale-result.json and compressed log: 242 complete generated
  cases, interrupted at the preset overall budget. Stalled-thread artifacts record
  the timeout snapshot; stack attachment was denied. The filename is diagnostic
  convention, not proof that the process stalled.
- retention-saved-regressions and retention-completion-red/green: saved seed path
  qualification and the real writer-owner completion assertion's RED/GREEN.
- final-review.md and progress.md: one fresh review, fix disposition and all rulings.

Local evidence only. Historical issue 1045 and the full 256-case slow-sync gate
remain open. No full-workspace, hosted, release or M5 qualification is claimed.
