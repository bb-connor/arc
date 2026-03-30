# Phase 103: External Signed Appraisal Result Import/Export and Policy Mapping - Context

## Goal

Add signed appraisal result import and export plus explicit local policy mapping
rules so ARC can exchange bounded external appraisal artifacts without trusting
raw foreign evidence directly.

## Why This Phase Exists

After the common artifact and normalized vocabulary exist, ARC still needs an
exchange contract that preserves provenance and keeps local trust activation
explicit.

## Scope

- signed appraisal export artifacts
- signed appraisal import path with verifier and issuer provenance
- local policy-mapping rules from imported results into ARC trust decisions
- fail-closed replay, staleness, signature, and unsupported-claim handling

## Out of Scope

- mixed-provider qualification closure
- public discovery or trust-bundle publication
- wider verifier federation and portfolio composition
