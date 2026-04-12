# MERCURY Demo Storyboard

**Date:** 2026-04-02  
**Audience:** founders, product, GTM, evaluators, and design partners

---

## 1. Story Constraint

Tell one story only:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

Do not widen the demo into generic AI governance, best-execution proof, or
multi-system integration.

---

## 2. Scenes

### Scene 1: Freeze the workflow

Show `scenario.json` and explain that MERCURY is the finance-specific product
layer on ARC, not a second runtime or second truth contract.

### Scene 2: Proposal enters the shadow lane

Open `primary/events.json` and show the proposal step entering the replay or
shadow workflow.

### Scene 3: Approval becomes signed truth

Explain that ARC emits the signed receipts and checkpoints while MERCURY adds
workflow semantics and retained-artifact meaning.

### Scene 4: Controlled release lands

Show `primary/evidence/manifest.json` and explain that ARC evidence export is
still the canonical substrate.

### Scene 5: Proof package is wrapped, not invented

Open `primary/proof-package.json` and explain that `Proof Package v1` binds
back to the verified ARC evidence export manifest hash.

### Scene 6: Inquiry package is derived safely

Open `primary/inquiry-package.json` and explain that inquiry material is a
reviewed export, not a rewrite of truth.

### Scene 7: Independent verification

Use the commands from
[EVALUATOR_VERIFICATION_FLOW.md](EVALUATOR_VERIFICATION_FLOW.md) to verify the
primary proof package and the inquiry package.

### Scene 8: Rollback stays in the same contract family

Show `rollback/proof-package.json` and explain that rollback is not a special
sidecar system. It is the same workflow family with different chronology and
approval state.

### Scene 9: Decision

End on one explicit question:

- move the same workflow into supervised-live productionization
- keep it in replay/shadow mode for more evidence gathering
- stop and do not broaden scope

Do not end with connector wish lists.
