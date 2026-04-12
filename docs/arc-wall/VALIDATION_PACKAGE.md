# ARC-Wall Validation Package

**Date:** 2026-04-03  
**Milestone:** `v2.50`

---

## Purpose

`control-path validate` is the canonical close-out command for the bounded
ARC-Wall lane. It generates the control-path bundle, writes the validation
report, and emits one explicit expansion decision instead of implying a generic
barrier platform or multi-product hardening program.

---

## Command

```bash
cargo run -p arc-wall -- control-path validate --output target/arc-wall-control-path-validation
```

---

## Output Layout

```text
target/arc-wall-control-path-validation/
├── control-path/
│   ├── control-profile.json
│   ├── policy-snapshot.json
│   ├── authorization-context.json
│   ├── guard-outcome.json
│   ├── denied-access-record.json
│   ├── buyer-review-package.json
│   ├── control-package.json
│   ├── control-path-summary.json
│   └── arc-evidence/
├── validation-report.json
└── expansion-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> ARC-Wall can record one denied cross-domain tool-access event for one
> `control_room_barrier_review` buyer motion using one fail-closed
> `tool_access_domain_boundary` control surface on ARC without turning MERCURY
> into ARC-Wall or widening into a generic barrier platform.

---

## Non-Claims

This package does not claim:

- multiple buyer motions
- complete information-barrier coverage
- generic barrier-platform breadth
- MERCURY workflow evidence readiness
- multi-product platform hardening
