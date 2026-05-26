# Research Paper Swarm Wave 3 Termination Recheck

Date: 2026-05-19.

Scope: fresh post-repair review after Wave 2, followed by a narrow local repair pass on the issues all reviewers agreed were still swarm-actionable.

## Fresh Reviewers

1. Fresh New Reader.
   - Verdict: parent, sensor, agentic, and bilateral all needed revision before submission.
   - Reversible-action: kill or pivot.
   - Delegated-emergency-authority: human-only defer.
   - Main actionable findings: parent abstract proof-scope drift, sensor retired-assumption and checklist drift, bilateral venue/status drift.

2. Fresh Adversarial PC Reviewer.
   - Verdict: bilateral was risky because anonymization, venue/status, and formal-artifact metadata could trigger desk rejection.
   - Main actionable findings: bilateral affiliation exposed `Chio Project`, Lean artifact comment overstated load-bearing scope, BilateralAccept was missing from formal metadata, sensor checklist still claimed pass.
   - Non-actionable findings: reversible needs Lean/runtime work, delegated needs legal review.

3. Fresh Build and Artifact Auditor.
   - Verdict: parent, sensor, and agentic PDF readiness are blocked by missing TeX and Poppler tools; bilateral metadata was incomplete; reversible remains artifact-blocked.
   - Commands reported clean: `git diff --check`, changed-file no-em-dash scan, `lake build`, JSON/TOML parse checks.
   - Commands reported blocked: parent and sensor `make preflight` fail because `pdflatex`, `bibtex`, `pdfinfo`, and `pdftotext` are absent.
   - Follow-up: Homebrew TeX Live and Poppler were installed locally after this review, unblocking the PDF gates below.

## Narrow Repair After Review

Patched locally:
- Parent abstracts now state that Lean covers bounded treaty and amendment claims, not the whole Rust implementation.
- Sensor abstracts, conclusion, and checklist now say the substrate-honest assumption is strictly strengthened and falsifiable, not retired.
- Sensor checklist verdict now records the current checkout as blocked until `make submit-check` reruns after source changes.
- Bilateral author metadata is anonymized to `Anonymous Institution`.
- Bilateral Lean comments now frame `freestanding_accept_set_theorem` as a schema-alignment theorem, not a load-bearing runtime security theorem.
- Bilateral formal sketch now reports the current axiom footprint: `propext` only.
- `formal/proof-manifest.toml` and `formal/theorem-inventory.json` now inventory `BilateralAccept` and its three corollaries.
- Bilateral README, venue memo, and completion memo now target an 8-10 page compact full-format USENIX paper, not a nonexistent USENIX short-paper class.
- Agentic grammar text now states that the local grammar contract is sufficient for the workshop argument if the companion substrate paper remains unpublished at submission time.
- Sensor `submit-check-acmart` now treats `paper.tex` as a long generic draft compile gate. The page-limited submission gate remains `paper-usenix.tex`.

## Post-Repair Verification

Commands run after the narrow repair:
- `git diff --check` exited 0.
- `jq . formal/theorem-inventory.json >/dev/null` exited 0.
- `python3 -c "import json, pathlib, tomllib; json.load(open('formal/theorem-inventory.json')); tomllib.load(open('formal/proof-manifest.toml','rb'))"` exited 0.
- Targeted no-em-dash scan over changed and untracked files exited 1 with no matches.
- Targeted stale-claim scans for the repaired Wave 3 issues exited 1 with no matches.
- `cd formal/lean4/Chio && lake build` exited 0 with `Build completed successfully (23 jobs).`
- Bilateral axiom query via `lake env lean --stdin` exited 0; all four queried BilateralAccept results depend only on `[propext]`.
- Homebrew `texlive` and `poppler` install supplied `pdflatex`, `bibtex`, `pdfinfo`, `pdftotext`, and `latexmk`.
- Parent `make submit-check` exited 0; `paper-usenix.pdf` has 17 total pages and 13 body pages, within the 13-page submission body limit.
- Parent `make submit-check-acmart` exited 0; `paper.pdf` has 13 total pages and 11 body pages.
- Sensor `make submit-check` exited 0; `paper-usenix.pdf` has 16 total pages and 12 body pages, within the 13-page submission body limit.
- Sensor `make submit-check-acmart` exited 0 after the target was corrected to a generic draft compile gate; `paper.pdf` builds to 24 pages and passes log and BibTeX checks.
- Agentic `latexmk -pdf -interaction=nonstopmode -halt-on-error -file-line-error paper.tex` exited 0; log and BibTeX scans found no fatal, undefined-reference, citation, or BibTeX warning markers, and `paper.pdf` has 14 pages.
- Bilateral `latexmk -pdf -interaction=nonstopmode -halt-on-error -file-line-error paper.tex` exited 0; log and BibTeX scans found no fatal, undefined-reference, citation, or BibTeX warning markers, and `paper.pdf` has 11 pages.

## Readiness State

- `programmable-sovereignty`: automated text, Lean, USENIX PDF, and fallback PDF gates pass. Remaining controls are human appendix review, venue choice, and submission actions.
- `sensor-grounded-admission`: automated text and USENIX PDF gates pass; generic draft compile gate passes. Remaining controls are double-blind handling of the parent Chio citation, venue choice, and submission actions.
- `agentic-tool-safety`: workshop-viable with LaTeX build passing. Remaining controls are workshop choice and optional parent-paper citation strategy.
- `bilateral-receipt-admission`: desk-reject grade metadata drift is fixed and LaTeX build passes. Remaining controls are venue choice and final appendix/submission decisions.
- `reversible-action`: kill or pivot until live `sorry` gates and runtime support are addressed.
- `delegated-emergency-authority`: human-only defer until a qualified legal reviewer participates.

## Termination Decision

Do not dispatch another broad repair swarm now. Remaining items are:
- Human gates: legal review for delegated emergency authority, venue choices, appendix review, and submission actions.
- Larger implementation gates: reversible-action Lean and runtime work.

Recommended next swarm wave: none until the human explicitly chooses to invest in reversible-action Lean/runtime work or delegated legal-review preparation.
