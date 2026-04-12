# ARC-Wall Documentation Suite

ARC-Wall is a companion product on ARC. It records tool-boundary control
evidence for information-domain separation workflows while reusing ARC's
signing, checkpoint, publication, and verification substrate.

ARC-Wall is not MERCURY renamed. MERCURY remains the trading-workflow evidence
product. ARC-Wall is the bounded companion-product lane for one information-
domain control buyer motion.

---

## Canonical Commands

Export the bounded control-path package and ARC evidence bundle:

```bash
cargo run -p arc-wall -- control-path export --output target/arc-wall-control-path-export
```

Generate the validation package and explicit expansion decision:

```bash
cargo run -p arc-wall -- control-path validate --output target/arc-wall-control-path-validation
```

---

## Document Map

- [CONTROL_PATH.md](CONTROL_PATH.md) — selected buyer motion, bounded control
  surface, owners, non-goals, and canonical commands
- [OPERATIONS.md](OPERATIONS.md) — fail-closed operating model and recovery
  posture
- [VALIDATION_PACKAGE.md](VALIDATION_PACKAGE.md) — output layout and supported
  claim for the validation package
- [DECISION_RECORD.md](DECISION_RECORD.md) — explicit expansion decision for
  the bounded ARC-Wall lane
- [../mercury/ARC_WALL_BRIEF.md](../mercury/ARC_WALL_BRIEF.md) — companion-
  product brief and problem statement
- [../mercury/PRODUCT_SURFACE_BOUNDARIES.md](../mercury/PRODUCT_SURFACE_BOUNDARIES.md) —
  shared ARC substrate seams plus the separate MERCURY and ARC-Wall product
  boundaries
