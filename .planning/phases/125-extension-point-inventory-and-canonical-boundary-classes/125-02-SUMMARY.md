# Summary 125-02

Separated canonical ARC truth from replaceable extension seams.

## Delivered

- modeled canonical truth surfaces separately from extension points in
  `crates/arc-core/src/extension.rs`
- recorded those canonical-versus-replaceable classes in
  `docs/standards/ARC_EXTENSION_INVENTORY.json`
- documented the split in `docs/standards/ARC_EXTENSION_SDK_PROFILE.md`

## Result

ARC now has one reviewable statement of which surfaces extensions may replace
and which surfaces remain ARC-owned truth.
