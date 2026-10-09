---
id: "SEC-1160-COLDSTATE"
title: "Authenticated cold state for native security history (FINAL-F01 follow-up from #1160)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/platform/chio-store-sqlite/src/security_state/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 24.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Owner decision 2026-10-09 (`pr1160-f01-bounded-landing`): #1160 landed with bounded FINAL-F01. Lineage labels, principal labels, genesis epochs (with the per-principal epoch index) and declassification rows still count toward the 65,536 native current-row budget and cannot be deleted safely. Implement authenticated cold state so that history moves out of the hot budget without being forgotten.

Start from the lane design `claude-pr1160-evidence/hammer/tickets/final-f01-cold-state-design.md` (ws2 coord lane, sha256 prefix dc5b4c9d003fe215), with these binding corrections from Root (2026-10-09T21:10:25Z) and the planner:
- rehydrate the exact authenticated epoch image, never a manufactured COPY_EPOCH, and keep a retained authenticated marker for cross-tier transition-id uniqueness;
- authenticated per-(tenant, principal, epoch) membership plus a monotone principal-has-history entry, with no unbounded per-principal sorted set and no prefix scans;
- no O(cold-history) work at open or admission; authenticate every cold lookup and fail closed on a missing or corrupt proof node; a full scrub is an explicit offline operation;
- versioned or content-addressed cold values with an authenticated current-version pointer, and canonical domain-separated key and value encodings;
- a hot-missing fallback can never resurrect an older cold image after a newer hot incarnation was removed or corrupted;
- declassification lifetime state is a fourth class, covering retention, replay and spend semantics;
- atomic cold insert, hot delete, record and commit in one checkpoint transaction; schema migration and pinned-catalog re-pins planned with the integrator.

## Acceptance

- Original RED, then GREEN, for each of these:
  - lineage-only churn past about 32K roots;
  - mixed lineage plus session churn;
  - declassification churn;
  - recovery after churn, with no restart;
  - a cold-to-hot update followed by hot-row removal, which is refused with no resurrection;
  - crash at each checkpoint cutpoint;
  - replay of an older checkpoint, which is refused.
- A delegated principal joining a cold lineage inherits its taint, and a reused principal id never reads bottom.
- The landing docs' capacity-ceiling note from #1160 is removed or updated.
- Strict clippy and fmt pass on every crate touched, with no unwrap or expect.

## Log
- 2026-10-09T21:28:44Z connor: created
