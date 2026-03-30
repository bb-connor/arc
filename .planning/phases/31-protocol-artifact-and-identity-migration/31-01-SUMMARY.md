# Phase 31 Plan 01 Summary

## What Changed

- made ARC schema identifiers the primary issuance contract for DPoP,
  checkpoints, portable-trust artifacts, certification artifacts, evidence
  export packages, and registry/version markers
- kept explicit legacy `arc.*` constants and compatibility helpers so
  historical artifacts still validate or import under the documented migration
  contract
- normalized persisted registries toward ARC-primary versions when old
  ARC-era files are loaded and rewritten

## Result

New issuance now presents ARC-first protocol and artifact identities without
silently orphaning the existing installed base.
