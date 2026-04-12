# MERCURY Supervised-Live Qualification Package

**Date:** 2026-04-02  
**Audience:** design-partner reviewers, product, engineering, compliance, and commercial owners

---

## 1. Purpose

This document describes the canonical reviewer package for MERCURY's
same-workflow supervised-live bridge. The package is intentionally narrow: it
qualifies the controlled release, rollback, and inquiry workflow for one
supervised-live decision and nothing broader.

---

## 2. Generate The Package

Use the repo-native command:

```bash
cargo run -p arc-mercury -- supervised-live qualify \
  --output target/mercury-supervised-live-qualification
```

That command generates:

- a healthy supervised-live corpus for the same workflow
- the pilot rollback anchor for the same workflow family
- `qualification-report.json`
- `reviewer-package.json`

---

## 3. Package Contents

| Path | Purpose |
|------|---------|
| `target/mercury-supervised-live-qualification/supervised-live/` | Healthy supervised-live capture, proof, inquiry, and verification outputs |
| `target/mercury-supervised-live-qualification/pilot/` | Pilot primary and rollback corpus used as the rollback anchor |
| `target/mercury-supervised-live-qualification/qualification-report.json` | Machine-readable bridge summary with decision, workflow boundary, and artifact references |
| `target/mercury-supervised-live-qualification/reviewer-package.json` | Reviewer-oriented manifest that points to the corpus and the governing docs |

Canonical document references inside the reviewer package:

- [SUPERVISED_LIVE_BRIDGE.md](SUPERVISED_LIVE_BRIDGE.md)
- [SUPERVISED_LIVE_OPERATING_MODEL.md](SUPERVISED_LIVE_OPERATING_MODEL.md)
- [SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md](SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md)
- [SUPERVISED_LIVE_DECISION_RECORD.md](SUPERVISED_LIVE_DECISION_RECORD.md)

---

## 4. Claims The Package Supports

The package supports these claims:

- MERCURY can generate live-mode evidence for the same governed workflow using
  the existing ARC and MERCURY proof contracts
- supervised-live export is gated by explicit approval, rollback, health, and
  interruption state
- the rollback path remains bounded and reviewable in the same workflow family
- the operating boundary, fail-closed rules, and bridge-close outcome are
  explicit

The package does **not** support these claims:

- best-execution proof
- generic OMS/EMS or FIX coverage
- multi-workflow rollout
- broader governance, downstream-consumer, or OEM approval

---

## 5. Reviewer Checklist

Reviewers should confirm:

1. the supervised-live proof and inquiry verification outputs pass
2. the rollback anchor remains within the same workflow family
3. the bridge, operating model, and runbook docs describe the same fail-closed
   boundary as the generated artifacts
4. the decision record stays limited to one same-workflow proceed/defer/stop
   outcome

---

## 6. Current Bridge Outcome

The current local bridge-close artifact is:

- `proceed` to one same-workflow supervised-live design-partner deployment
  review under the documented operating envelope

That does not approve broader governance, downstream-consumer, connector, or
OEM expansion. Those remain future milestone choices.
