# Phase 30 Plan 03 Summary

## What Changed

- updated release and parity scripts to target `arc-cli`, `arc-conformance`,
  and the renamed SDK package identities
- added ARC-primary conformance bin names while keeping the legacy
  `arc-conformance-*` aliases
- refreshed the root README and conformance README so the quick-start and
  packaging surfaces are ARC-first
- switched the conformance harness to prefer the `arc` binary while still
  falling back to `arc` during the compatibility window

## Result

The ARC package and binary rename is now exercised by the repo’s active build,
conformance, and release-tooling surfaces instead of living only in metadata.
