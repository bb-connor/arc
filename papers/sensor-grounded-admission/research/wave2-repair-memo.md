# Wave 2 Repair Memo

Date: 2026-05-19.

Changed:
- `Makefile` now has the same fail-closed preflight semantics as the parent paper.
- `paper-usenix.tex` now places Open Science and Ethics appendices before references.
- `SUBMISSION-CHECKLIST.md` no longer claims current green PDF verification in an environment missing TeX tools.
- `README.md`, `sections/01-introduction.tex`, `sections/03-substrate.tex`, and `sections/09-limitations.tex` calibrate sensor, key-custody, and hardware-rooted future-work claims.

Verification:
- `git diff --check` passed after integration.
- Targeted no-em-dash scan passed for changed files.
- `make preflight` fails closed because local TeX and Poppler tools are not installed.

Remaining:
- Run the full USENIX PDF gate after installing `pdflatex`, `bibtex`, `pdfinfo`, and `pdftotext`.
- Review same-key and hardware-rooted language again if the sensor paper moves from workshop or submission package to camera-ready paper.
