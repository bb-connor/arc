# Plan 161-03 Summary

Qualified the supported and unsupported Functions fallback modes.

## Delivered

- `crates/arc-anchor/src/functions.rs`
- `docs/standards/ARC_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json`

## Notes

The shipped tests now cover verified responses, over-value rejection, and
batch-root mismatch so unsupported EVM verification modes stay fail closed.
