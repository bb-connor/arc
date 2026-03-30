# Phase 37 Context

## Goal

Propagate enterprise identity context into portable credentials and federated
trust artifacts without silently widening trust.

## Current Code Reality

- `arc-credentials` already issues and verifies passports, verifier policies,
  and presentation artifacts, but enterprise-derived identity provenance is not
  yet a first-class portable-trust field.
- `arc-cli` already exposes enterprise federation administration plus passport
  issuance and verification flows, so the core operator surfaces exist.
- Imported federated evidence remains intentionally isolated from local receipt
  history, which is a good guardrail but leaves a gap between federation
  identity context and portable-trust artifacts.
- Certification discovery and cross-org reputation sharing in later phases need
  one explicit, fail-closed identity provenance model before they can safely
  reuse remote trust inputs.

## Decisions For This Phase

- Represent enterprise identity provenance explicitly rather than as ad hoc
  metadata embedded only in CLI outputs.
- Keep imported identity context fail-closed: federation inputs may inform
  verification, but they must not silently elevate local authority.
- Reuse the existing passport and verifier-policy artifact families instead of
  inventing a parallel identity channel.
- Make the propagated identity lineage operator-visible in CLI and trust-control
  surfaces.

## Risks

- Enterprise identity context can accidentally widen trust if provider-backed
- claims become implicit local authority.
- Multi-issuer portable trust already has complex subject semantics, so new
  identity provenance fields must not create contradictory joins.
- Distribution and reporting surfaces can drift if the data model is threaded
  through artifacts but not through operator tools.

## Phase 37 Execution Shape

- 37-01: define the enterprise-identity provenance model
- 37-02: thread enterprise identity context through issuance and verification
- 37-03: add fail-closed docs and regression coverage
