# Phase 31 Plan 03 Summary

## What Changed

- updated the protocol spec, portable-trust profile, passport guide, DID
  method guide, and identity-transition note to reflect the shipped ARC
  dual-stack contract
- documented `did:arc` as the frozen currently shipped DID method and
  `did:arc` as a later phase rather than pretending the identity migration is
  already complete
- aligned spec language to the actual implementation: ARC-primary artifact
  issuance where shipped, legacy `arc.*` verification/import support where
  compatibility is required

## Result

The spec and portable-trust docs now describe one coherent ARC migration model
instead of a mixed aspirational rename story.
