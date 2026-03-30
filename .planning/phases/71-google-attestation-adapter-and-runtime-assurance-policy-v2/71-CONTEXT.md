# Phase 71: Google Attestation Adapter and Runtime-Assurance Policy v2 - Context

## Goal

Add a Google attestation adapter and evolve runtime-assurance policy so ARC
can consume multiple verifier families without pretending their claims are
globally identical.

## Why This Phase Exists

Multi-cloud support is not just more adapters. ARC also needs a clearer policy
boundary for how appraisals from different verifier families affect issuance,
governed execution, and underwriting.

## Scope

- Google attestation adapter implementation
- conservative claim normalization for Google evidence
- runtime-assurance policy v2 over appraised verifier outputs
- integration of appraisals into issuance, governed execution, and
  underwriting reason codes

## Out of Scope

- public export and qualification closure
- marketplace or economic policy beyond runtime-assurance rebinding
- claiming full verifier-family equivalence
