# Research Paper Swarm Wave 2 Repair Summary

Date: 2026-05-19.

Scope: repair the highest-impact Wave 1 findings that did not require human legal judgment, live measurements, paper submission, or new theorem work.

## Repair Agents

1. USENIX packaging and build harness.
   - Changed parent and sensor Makefiles so TeX, BibTeX, PDF metadata, and PDF text extraction tools must exist before submit checks run.
   - Added parent USENIX Open Science and Ethics appendices, and moved sensor appendices ahead of references.
   - Updated the sensor checklist to stop claiming a green PDF gate in the current local environment.

2. Bilateral verifier and formal-claim calibration.
   - Normalized the bilateral binding tuple to ten named hash fields.
   - Split verifier trust-store membership into its own rejection code, `trust-store-miss`.
   - Reframed Lean coverage as a schema-alignment witness over three abstract gates rather than a proof of the full runtime verifier.

3. Agentic claim calibration.
   - Narrowed the workshop paper to mediated, correctly classified, single-envelope tool execution.
   - Replaced rollback language around `db.dump` with bilateral-consent language.
   - Moved collusion, strategic composition, operator manipulation, and TOCTOU risks into explicit threat-model and limitations text.

4. Parent and sensor claim calibration.
   - Narrowed parent first-page claims and evaluation scope.
   - Corrected EU GPAI Code phrasing.
   - Replaced stale sensor claims about retired assumptions with falsifiable and strengthened claims.

## Orchestrator Integration

Additional active-section fixes after worker return:
- Updated remaining bilateral active sections from five-code to six-code rejection language.
- Added `trust-store-miss` to the implementation table and attack discussion.
- Rewrote remaining agentic discussion guarantees to conditional mediated-dispatch language.

## Verification

Commands run after integration:
- `git diff --check` exited 0.
- Targeted stale-claim `rg` search over active bilateral and agentic sections exited 1 with no matches.
- Targeted no-em-dash `rg` search over changed files exited 1 with no matches.
- `cd formal/lean4/Chio && lake build` exited 0 with `Build completed successfully (23 jobs).`
- `make preflight` in `papers/programmable-sovereignty` exited 2 because `pdflatex`, `bibtex`, `pdfinfo`, and `pdftotext` are not installed.
- `make preflight` in `papers/sensor-grounded-admission` exited 2 for the same missing tools.

## Remaining Gates

- Full LaTeX PDF builds are blocked until local TeX and Poppler tools are installed.
- Reversible-action remains frozen or pivoted until Lean and runtime support land.
- Delegated-emergency-authority remains legal-circulation material until a qualified legal reviewer participates.
- No human-only actions were taken.
