# MERCURY Evaluator Verification Flow

**Date:** 2026-04-02  
**Audience:** design partners, compliance reviewers, security reviewers, and technical evaluators

---

## 1. Generate The Corpus

From the repository root:

```bash
cargo run -p chio-mercury -- pilot export --output target/mercury-pilot
```

This creates the primary and rollback corpus described in
[PILOT_RUNBOOK.md](PILOT_RUNBOOK.md).

---

## 2. Verify The Primary Proof Package

```bash
cargo run -p chio-mercury -- --json verify \
  --input target/mercury-pilot/primary/proof-package.json
```

Expected signals:

- `packageKind = "proof"`
- `workflowId = "workflow-release-control"`
- `receiptCount = 4`

---

## 3. Verify The Primary Inquiry Package

```bash
cargo run -p chio-mercury -- --json verify \
  --input target/mercury-pilot/primary/inquiry-package.json
```

Expected signals:

- `packageKind = "inquiry"`
- `workflowId = "workflow-release-control"`
- `verifierEquivalent = false`

The inquiry package is intentionally a reviewed export, not a second truth
bundle.

---

## 4. Verify The Rollback Variant

```bash
cargo run -p chio-mercury -- --json verify \
  --input target/mercury-pilot/rollback/proof-package.json
```

Expected signals:

- `packageKind = "proof"`
- `workflowId = "workflow-release-control"`
- `receiptCount = 4`

This shows rollback remains inside the same proof contract family.

---

## 5. Optional Explain Mode

For human-readable step output:

```bash
cargo run -p chio-mercury -- verify \
  --input target/mercury-pilot/primary/proof-package.json \
  --explain
```

Use this when walking a reviewer through why the package passes.

---

## 6. What To Reject

Treat the corpus as invalid if any of these are false:

- the proof package does not bind to a verified Chio evidence export
- the inquiry package verifies as proof-equivalent when it should be a reviewed
  export
- the rollback variant requires a separate contract or separate verification
  path
- the workflow ID drifts across the primary and rollback packages
