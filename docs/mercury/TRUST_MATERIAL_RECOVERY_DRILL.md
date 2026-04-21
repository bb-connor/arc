# Trust-Material Recovery Drill

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This drill defines one shared recovery path for the Chio-owned trust material
used by the current MERCURY plus Chio-Wall product set.

---

## Covered Material

- `receipt-signing-keys`
- `checkpoint-publication-keys`
- `product-release-packaging-approvals`

---

## Recovery Sequence

1. Pause both current product release lanes through `chio-release-control`.
2. Confirm shared custody state through `chio-key-custody`.
3. Rotate or restore the shared trust material through Chio-owned custody.
4. Resume only the product lanes that pass current product-surface validation.

---

## Success Conditions

- both product lanes remain paused until shared trust material is restored
- recovery evidence names Chio-owned custody and release owners plus product-
  local rollback contacts
- resumption is blocked unless the current hardening validation package passes

---

## Canonical Command

```bash
cargo run -p chio-cli -- product-surface export --output target/chio-product-surface-hardening-export
```

The export package writes `trust-material-recovery-drill.json`.
