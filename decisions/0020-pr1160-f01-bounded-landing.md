# #1160 lands with bounded FINAL-F01; authenticated cold state is a P1 follow-up gating G5

Decided by Connor on 2026-10-09. Fixing FINAL-F01 (native session churn exhausting the 65,536 current-row budget) showed that lineage labels, principal labels, genesis epochs and declassification rows cannot be deleted safely in the current store model. A later delegated principal must still inherit a lineage's taint, and a reused principal id must not restart at bottom. The full fix is authenticated cold state: a sparse-Merkle-authenticated cold tier, checkpoint record v2, and re-pins of three pinned catalogs. The agents estimate it at several days.

Ruling: #1160 lands with the bounded F01 set:
- option A session eviction (exact dominance, no fence, no non-terminal context, bounded fail-closed scans);
- FINAL-F12, a second-lineage refresh fix;
- a typed, retryable capacity refusal before the global bound;
- the per-admitted-operation completion reservation;
- the new-identity floor;
- a stated per-principal share.

Landing docs state:
- the ceiling (about 32K lineage roots, declassification rows included);
- the refusal error;
- that cold state is the tracked fix.

Follow-up item SEC-1160-COLDSTATE (P1) owns cold state. It must close before the outside-team preview (G5-PREVIEW), not before #1160. The planner's and Root's design corrections from 2026-10-09 apply to it. No cap is raised silently, no lineage or authorization history is dropped, and no generation is reset meanwhile.
