# Phase 102: Normalized Claim Vocabulary and Reason Taxonomy - Context

## Goal

Standardize the portable claim vocabulary and reason taxonomy shared across
verifier families so external appraisal results can be compared without
pretending vendor-specific claims are identical.

## Why This Phase Exists

The common appraisal shell from phase 101 is not enough unless ARC also defines
what normalized claims and reasons mean across heterogeneous verifier families.

## Scope

- portable normalized claim names and categories
- reason-code taxonomy for acceptance, degradation, rejection, and uncertainty
- mapping rules from provider-specific signals into normalized claims
- fail-closed handling for unmapped or contradictory reason semantics

## Out of Scope

- signed import or export of external results
- verifier federation or discovery surfaces
- live policy import across operators
