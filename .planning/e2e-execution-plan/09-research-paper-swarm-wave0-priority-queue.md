# Research Paper Swarm Wave 0 Priority Queue

Date: 2026-05-19
Branch: `research/programmable-sovereignty-papers`
Scope: six paper directories named in `08-research-paper-swarm-goal-prompt.md`

## Agents Run

- Wave 0A New Reader Review: first-time program-committee read across all six papers.
- Wave 0B Paper-Line Cartographer: synthesis read across the publication line.
- Wave 0C Build and Artifact Auditor: reproducibility and artifact inspection.

All three agents were read-only. No paper text, bibliography, LaTeX, or Lean source was edited in Wave 0.

## Paper Verdicts

| Paper | Wave 0 synthesis verdict | Main reason |
|---|---|---|
| `papers/programmable-sovereignty/` | revise-before-submit | Strong substrate paper, but USENIX package still needs mandatory Open Science and Ethics appendices or the readiness claim must be narrowed. |
| `papers/sensor-grounded-admission/` | revise-before-submit | Strongest technical extension, but checklist state is stale against the current appendices and the double-blind Chio citation policy remains a human gate. |
| `papers/agentic-tool-safety/` | revise-before-submit | Workshop-viable, but it depends on parent-paper formal claims and still has venue-template and citation-strength gates. |
| `papers/bilateral-receipt-admission/` | revise-before-submit | Technically close, but abstract density, salami-slice risk, and stale README status make it sequence-sensitive. |
| `papers/reversible-action/` | kill/pivot until gates close | The headline Lean theorem is not mechanized and deployment gaps make the systems claim aspirational. |
| `papers/delegated-emergency-authority/` | risky | Good circulation draft, but not publication-ready without legal review, citation hardening, and formatting conversion. |

## Priority Queue

### P0: Blocks Submission Or Correctness

1. `papers/reversible-action/theorems.lean:207-220,267-283` has live `sorry` gaps and is not registered in Lake. Do not treat this paper as a submission candidate until the headline theorem gate closes.
2. `papers/reversible-action/sections/09-limitations.tex:31-59` states missing scheduler, missing inverse executors, no bilateral wiring, and crash-window weaknesses. These are not paper-polish issues; they block the claimed systems story.

### P1: Likely Reviewer Rejection

1. `papers/programmable-sovereignty/paper-usenix.tex:60-68` ends after bibliography with no Open Science or Ethics appendix. The planning handoff already lists these as human gates in `.planning/e2e-execution-plan/execution-complete.md:76-80`.
2. `papers/programmable-sovereignty/Makefile:50-72` and `papers/sensor-grounded-admission/Makefile:48-70` echo TeX and BibTeX exit codes after `;`, which can mask failing build passes. The pass criteria at lines 8-15 say failures must abort.
3. `papers/programmable-sovereignty/Makefile:31-34,122-147` and `papers/sensor-grounded-admission/Makefile:29-32,120-145` require `pdfinfo` and `pdftotext`, but the dependency is not preflighted. In this environment `pdflatex`, `bibtex`, and `pdfinfo` are absent.
4. `papers/sensor-grounded-admission/SUBMISSION-CHECKLIST.md:71-80` says Open Science and Ethics appendices are not written, while `papers/sensor-grounded-admission/paper-usenix.tex:67-69` includes both appendices. Refresh the checklist and page counts before calling the package ready.
5. `papers/sensor-grounded-admission/sections/01-introduction.tex:12,24` uses "retired assumption" and "retires" language even though the construction makes sensor posture falsifiable and auditor-addressable rather than independently detecting false sensor claims.
6. `papers/bilateral-receipt-admission/paper.tex:38-39` has an abstract dense enough to make a first-page rejection easy. It also carries the parent-overlap disclosure in the abstract, which must be aligned with the final venue strategy.
7. `papers/bilateral-receipt-admission/VENUE-DECISION.md:110-129,153-158` flags parent plus bilateral salami-slice risk. The paper needs sequence discipline and overlap disclosure before submission.
8. `papers/delegated-emergency-authority/README.md:56-75` and `papers/delegated-emergency-authority/sections/07-limits.tex:123-141` explicitly require legal-scholar review for several load-bearing claims.

### P2: Material Odds Improvement

1. `papers/programmable-sovereignty/sections/01-introduction.tex:3` ties Rust checks, named Lean theorems, and canonical receipts into one sentence. Calibrate this so definitional bridges are not sold as full mechanized security proofs.
2. `papers/programmable-sovereignty/sections/06-evaluation.tex:19` and `papers/programmable-sovereignty/sections/10-conclusion.tex:3` leave adoption and external-counterparty evidence as visible gaps. Either make them future-work constraints earlier or provide stronger evidence.
3. `papers/sensor-grounded-admission/sections/01-introduction.tex:20` names an existential theorem with "separates" language while the degraded witness is the empty attestation. Calibrate the theorem name and prose to avoid a quantifier overclaim.
4. `papers/agentic-tool-safety/sections/04-formal-grammar.tex:4-5,65-77` depends on parent theorem support. Add enough self-contained grammar that the workshop paper does not ask reviewers to trust a companion submission.
5. `papers/agentic-tool-safety/sections/06-threat-model.tex` and `papers/agentic-tool-safety/sections/08-limitations.tex` should tighten operator manipulation, registry ownership, denial-of-service, multi-agent composition, and rollback-witness confidentiality.
6. `papers/bilateral-receipt-admission/README.md:36-38` says skeleton only despite a full paper and PDF. Reconcile status docs.
7. `papers/delegated-emergency-authority/README.md:89-94` says `bib.bib` is not present even though it exists. Reconcile status docs and law-review formatting state.

### P3: Nice To Have

1. Write a one-page cross-paper citation policy covering anonymous parent citation, Chio naming, related polity-layer phrasing, and when the bilateral primitive is cited as a separate contribution.
2. Add domain-ownership sentences across the line: parent owns substrate, sensor owns sensor-state admission, bilateral owns wire primitive, agentic owns AI-safety framing, reversible owns endpoint response, delegated owns legal grammar.
3. Normalize cross-references for bilateral cosignature in `agentic-tool-safety` and `reversible-action`.
4. Add per-paper build gates or explicit "not submission-gated" status for agentic, bilateral, reversible, and delegated drafts.

## Verification Performed By Orchestrator

- `lake build` in `formal/lean4/Chio` exited 0 with 23 jobs on 2026-05-19.
- Local `pdflatex`, `bibtex`, and `pdfinfo` are absent in this environment, so LaTeX rebuilds could not be reproduced here.
- No source edits were made in Wave 0, so no paper-specific LaTeX or Lean rebuild was required by an edit.

## Wave 1 Inputs

Wave 1 expert reviewers should treat the P0 and P1 queue above as the starting attack surface, but should not limit themselves to it. Repair agents may be dispatched only after Wave 1 findings are synthesized into disjoint file scopes.
