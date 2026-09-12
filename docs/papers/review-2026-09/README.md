# Whitepaper Review, September 2026

A comprehensive review of the two Chio whitepapers against the repository at `main` `fe5657020c`, conducted 2026-09-10 to 2026-09-11 with three waves of orchestrated, adversarially verified analysis and a full benchmark reproduction on the Linux Neoverse-N1 host the first paper describes.

Start with `01-executive-summary.md`. The method and every pinned fact are in `00-method-and-scope.md`. The roadmap is `10-roadmap.md`.

| File | What it is |
| --- | --- |
| `00-method-and-scope.md` | Method, waves, pinned facts, reproduction commands |
| `01-executive-summary.md` | The verdict, the ten most consequential findings, the recommended direction |
| `02-p1-claim-audit.md` | Paper 1 claim-by-claim audit, gate runs, benchmark reproduction, appendix of findings |
| `03-p2-claim-audit.md` | Paper 2 claim-by-claim audit, appendix of findings |
| `04-formal-evidence-audit.md` | What the cited theorems prove, the wider harness estate, assumption discipline |
| `05-cross-paper-consistency.md` | Contradiction matrix, the six-paper family, spec staleness |
| `06-foundational-paper-benchmark.md` | Rubric derived from foundational documents; both papers scored |
| `07-simulated-pc-reviews.md` | Six program-committee reviews of the papers as submitted |
| `08-the-thesis.md` | Five candidate theses, two judges, the recommended unified thesis |
| `09-claim-surface-and-landscape.md` | What Chio truthfully supports today; competitive and prior-art landscape |
| `10-roadmap.md` | Prioritized actions in four phases |
| `11-prose-and-structure-audit.md` | Reader-experience audit, missing related work, structural recommendations |
| `12-execution-record.md` | What phases 0 through 3 delivered, the status of every finding, and the measurements before and after |
| `findings.json` | Machine-readable findings with verifier verdicts and execution status |

Phases 0 through 3 of the roadmap were executed on the branch
`paper/roadmap-phase-0-1` in fourteen commits from `84f2d3eaff` to
`c76f19a062`. Read `12-execution-record.md` before acting on any document in
this set: 151 of the 172 findings are closed, and the measurements in the
tables below were superseded by a single clean-tree re-measurement.

The analysis in files `00` through `11` is advisory and changed no paper, spec,
or source file. House rule: no em dashes anywhere in this set.
