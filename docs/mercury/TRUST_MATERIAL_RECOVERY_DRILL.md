# Trust-Material Recovery Drill

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This drill defines one shared recovery path for the ARC-owned trust material
used by the current MERCURY plus ARC-Wall product set.

---

## Covered Material

- `receipt-signing-keys`
- `checkpoint-publication-keys`
- `product-release-packaging-approvals`

---

## Recovery Sequence

1. Pause both current product release lanes through `arc-release-control`.
2. Confirm shared custody state through `arc-key-custody`.
3. Rotate or restore the shared trust material through ARC-owned custody.
4. Resume only the product lanes that pass current product-surface validation.

---

## Success Conditions

- both product lanes remain paused until shared trust material is restored
- recovery evidence names ARC-owned custody and release owners plus product-
  local rollback contacts
- resumption is blocked unless the current hardening validation package passes

---

## Canonical Command

```bash
cargo run -p arc-cli -- product-surface export --output target/arc-product-surface-hardening-export
```

The export package writes `trust-material-recovery-drill.json`.
