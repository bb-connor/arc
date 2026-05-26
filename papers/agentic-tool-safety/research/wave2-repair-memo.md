# Wave 2 Repair Memo

Date: 2026-05-19.

Changed:
- `paper.tex` and the active sections now frame the contribution as mediated, correctly classified, single-envelope tool execution.
- `sections/05-implementation-sketch.tex` treats `db.dump` as a destructive bilateral-consent example, not as rollback.
- `sections/06-threat-model.tex` and `sections/08-limitations.tex` now name collusion, operator manipulation, strategic composition, TOCTOU, and registry risks.
- `sections/07-discussion.tex` now states admission-layer guarantees only under the paper's mediated-dispatch and independent-cosigner assumptions.

Verification:
- `git diff --check` passed after integration.
- Targeted no-em-dash scan passed for changed files.
- Targeted stale-guarantee search over active sections passed.

Remaining:
- Run LaTeX once local TeX tooling is available.
- Pick the specific NeurIPS 2026 workshop after workshop acceptances are public.
