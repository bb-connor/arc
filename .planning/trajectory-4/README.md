# Trajectory-4 Planning

Working drafts for trajectory-4. **Not normative** until scope-lock and `EXECUTION-BOARD.md` are authored.

## Doc layout

| File | Purpose |
|---|---|
| `SYNTHESIS-V2-INTEGRATED-PLAN.md` | **Active plan**. Four-tier scope, recommended scope-lock, 25-condition close bar. Revised after reviewer feedback. |
| `BRAINSTORM-V1-FEATURE-CATALOG.md` | Comprehensive catalog of every proposal from the 9-lens brainstorm (DX, perf/scale, capability, protocol, AI-frontier, TEE/HW, trust-graph, observability/SRE, codebase archaeology). ~126 distinct items with effort and impact ratings. Workspace ground-truth corrections from archaeology. |
| `REJECTED-IDEAS.md` | Every idea raised and rejected, with rationale. Recorded so future trajectories can revisit with fresh information. |
| `SYNTHESIS-V1-INTERNAL-ONLY.md` | Original substrate-hardening floor distilled from the 5-perspective scope debate (engineer-rigor, security-paranoid, compliance-vendor, customer-velocity, devil's-advocate). Superseded by v2 but retained as the perspective-debate record. |

## Reading order

For a fast scan: `SYNTHESIS-V2-INTEGRATED-PLAN.md`.

For deep context: read v1, then the catalog, then v2.

## Status

- 9 brainstorm agents reported.
- Reviewer pass identified 3 P1/P2 issues + 4 doc consistency nits + scope-lock recommendation.
- v2 revised to address every reviewer point.
- Recommended scope-lock: **T0 + T1.0 + T1.1 + T1.2 + T1.3 + T1.4 + T1.6 + T2.1 + one of {T1.5, T2.3}**, 12-15 weeks parallel / 18-20 weeks single-track. T2.2 hot-path cache becomes explicit stretch (gated on flame-graph profile).

## Next steps

1. User picks scope (recommended above, or a variation).
2. Author `EXECUTION-BOARD.md` with concrete tickets and milestone audit-doc skeletons under `.planning/trajectory-4/audits/`.
3. Begin Phase A (trj3 closeout finalization) on day 1.
