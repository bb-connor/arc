# Summary 127-01

Defined runtime envelopes and privilege boundaries for ARC extensions.

## Delivered

- added per-extension runtime envelopes with isolation, privilege, and
  evidence-mode fields in `crates/arc-core/src/extension.rs`
- mapped allowed privilege envelopes onto each extension point in
  `docs/standards/ARC_EXTENSION_INVENTORY.json`
- tied official components back to those same runtime envelopes

## Result

ARC now has one explicit statement of which privileges and deployment shapes a
custom implementation may use at each named seam.
