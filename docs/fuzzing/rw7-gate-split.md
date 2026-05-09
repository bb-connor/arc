# RW7 Gate Split

This branch is the minimal executable gate split from the quarantined
Wave 4A evidence gate tail.

## Branch Contract

- Source branch for this split: `codex/wave4a-evidence-gates-formal-kani`.
- Planning branch that must stay planning-only: `claude/charming-feistel-8595da`.
- Active gate branch: `codex/rw7-gate-split-620-628`.

## Included Here

- Bounded assurance gate script and behavioral regression test.
- Threat coverage mutants gate hardening and behavioral regression test.
- Mutants gate fail-closed handling for missing, empty, tiny, below-target,
  interrupted, and override-nonclosure outcomes.
- One CI hook that runs the bounded assurance regression test beside the
  existing structural shell gate tests.

Covered issue IDs: RW7-BI-P0-002, RW7-BI-P0-004, RW7-BI-P2-001,
RW7-HYG-P2-006, and the executable-gate part of RW7-EVID-P1-001.

## Still Quarantined In #628

The draft #628 tail still contains broad non-gate changes: Kani inventory
expansion, workflow restructuring, release metadata rewrites, planning docs,
evidence artifacts, and source or dependency churn. Those are intentionally
not part of this split branch. They should remain quarantined until reviewed
as their own merge unit or split into smaller ownership branches.

## Validation Scope

The merge signal for this branch is the executable gate suite:

- `bash scripts/tests/mutants-gate-missing-outcomes.test.sh`
- `bash scripts/tests/check-threat-coverage-mutants.test.sh`
- `bash scripts/tests/check-bounded-ship-bar.test.sh`
- `actionlint .github/workflows/ci.yml`
- changed-file punctuation scan for em dash and en dash
- clean diff review against the allowed gate scope
