# Phase 30 Plan 02 Summary

## What Changed

- made `arc` the primary CLI binary in `arc-cli`
- kept `arc` as an explicit compatibility binary alias
- renamed SDK package metadata to `@arc-protocol/sdk`, `arc-py`, and the
  `github.com/backbay-labs/arc/packages/sdk/arc-go` module path
- updated SDK release scripts, README surfaces, and package-smoke assertions to
  use the ARC identities

## Result

Operators and SDK consumers now see ARC as the canonical package and binary
surface, while the legacy `pact` entrypoint and Python import package remain as
documented compatibility shims for the transition window.
