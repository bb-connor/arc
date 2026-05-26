# Wave 2 Repair Memo

Date: 2026-05-19.

Changed:
- `Makefile` now has a fail-closed `preflight` gate for LaTeX, BibTeX, PDF page counting, and PDF text extraction tools.
- `paper-usenix.tex` now includes Open Science and Ethics appendices before references.
- `sections/01-introduction.tex`, `sections/06-evaluation.tex`, and `sections/07-discussion.tex` narrow first-page, evaluation, and regulatory claims.
- `sections/11-appendix-open-science.tex` and `sections/12-appendix-ethics.tex` provide USENIX appendix shells.

Verification:
- `git diff --check` passed after integration.
- Targeted no-em-dash scan passed for changed files.
- `make preflight` fails closed because local TeX and Poppler tools are not installed.

Remaining:
- Run the full USENIX PDF gate after installing `pdflatex`, `bibtex`, `pdfinfo`, and `pdftotext`.
- Human must review the appendix text before portal submission.
