# MERCURY Pilot Runbook

**Date:** 2026-04-02  
**Audience:** engineering, product, design-partner operations, and evaluators

---

## 1. Goal

Generate the canonical MERCURY design-partner corpus for the first workflow:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

The runbook uses the shipped repo command, not a hand-built artifact path.

---

## 2. Command

Run from the repository root:

```bash
cargo run -p arc-mercury -- pilot export --output target/mercury-pilot
```

If you already built the repo and have the binary on your path, the equivalent
command is:

```bash
mercury pilot export --output target/mercury-pilot
```

---

## 3. Output Tree

The command writes one deterministic corpus:

```text
target/mercury-pilot/
  scenario.json
  pilot-summary.json
  primary/
    events.json
    receipts.sqlite3
    bundle-manifest.json
    evidence/
    proof-package.json
    proof-verification.json
    inquiry-package.json
    inquiry-verification.json
  rollback/
    events.json
    receipts.sqlite3
    bundle-manifest.json
    evidence/
    proof-package.json
    proof-verification.json
```

Interpretation:

- `primary/` is the gold propose -> approve -> release -> inquiry flow
- `rollback/` is the rollback proof variant for the same workflow
- `scenario.json` is the typed Mercury-specific corpus definition
- `pilot-summary.json` is the machine-readable index for downstream docs and
  automation

---

## 4. What The Corpus Proves

The primary path demonstrates:

1. replay/shadow events can be turned into signed ARC receipts
2. those receipts can be checkpointed and exported through the canonical ARC
   evidence package
3. the exported package can be wrapped into `Proof Package v1`
4. a reviewed export can be derived as `Inquiry Package v1`
5. both packages can be verified independently through the shipped CLI

The rollback path demonstrates the same workflow can emit a bounded rollback
proof variant without redefining the package contract.

---

## 5. Expected Counts

- primary receipts: `4`
- rollback receipts: `4`
- primary packages: proof + inquiry
- rollback packages: proof only

Any deviation should be treated as a corpus regression.

---

## 6. Follow-On Checks

After export, run the evaluator-facing verification flow in
[EVALUATOR_VERIFICATION_FLOW.md](EVALUATOR_VERIFICATION_FLOW.md).

Use [DEMO_STORYBOARD.md](DEMO_STORYBOARD.md) when walking a partner or internal
reviewer through the corpus.

The pilot corpus remains the root of the later Mercury stack. Supervised-live,
governance, assurance, trust-network, and release-readiness packaging all
reuse this same workflow truth rather than opening a second release surface.
