# Phase 101: Common Appraisal Schema Split and Artifact Inventory - Context

## Goal

Define ARC's outward-facing appraisal artifact surface, separate raw evidence
from normalized appraisal truth, and inventory the migration boundary for all
existing verifier families.

## Why This Phase Exists

ARC already has multiple verifier adapters, but the full endgame needs one
portable appraisal contract before external result exchange or federation can
be claimed honestly.

## Scope

- common appraisal artifact structure and versioning boundary
- separation of raw evidence, verifier identity, normalized claims, and local policy
- inventory of Azure, AWS Nitro, Google, and existing ARC appraisal outputs
- migration rules for current adapter outputs into one portable contract

## Out of Scope

- normalized claim vocabulary details
- external signed import or export flows
- mixed-provider qualification and public boundary closure
