# Phase 105: Cross-Issuer Portfolios, Trust Packs, and Migration Semantics - Context

## Goal

Add bounded cross-issuer portfolios and trust packs so ARC can compose portable
identity and appraisal evidence across issuers without creating ambient trust.

## Why This Phase Exists

The full endgame needs multi-issuer portability, but ARC must keep portfolio
composition and trust activation explicit rather than treating discovery as
admission.

## Scope

- cross-issuer portfolio and trust-pack artifacts
- migration and import/export semantics across issuers
- explicit local activation and attenuation rules
- fail-closed handling for ambiguous issuer provenance

## Out of Scope

- public verifier discovery surfaces
- wider provider support over the shared appraisal substrate
- automatic trust admission from portfolio visibility
