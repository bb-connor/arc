# MERCURY Assurance Suite Operations

**Date:** 2026-04-03  
**Audience:** reviewer owners, assurance operators, and support teams

---

## Operating Model

The assurance-suite lane is a bounded reviewer-packaging path over the same
qualified workflow evidence already packaged by supervised-live qualification
and governance-workbench export.

The export path is:

1. generate the governance-workbench package over the qualified workflow
2. derive internal, auditor, and counterparty inquiry packages from the same
   proof package
3. write one disclosure profile, one review package, and one investigation
   package for each reviewer population
4. write one top-level assurance-suite package binding those artifacts

If any required artifact is missing or any reviewer population cannot be
generated truthfully, the export must fail closed.

---

## Required Checks

- the output directory is empty before export starts
- the supervised-live proof package verifies successfully before reviewer
  artifacts are generated
- the governance decision package exists and is reused rather than replaced
- every reviewer-population inquiry package verifies successfully
- each disclosure profile, review package, investigation package, and the
  top-level assurance-suite package validate against the bounded schema
- event IDs, source-record IDs, and idempotency keys remain present in every
  investigation package

---

## Failure Recovery

- **Missing qualification or governance artifact:** stop export, regenerate
  from the same governed workflow path, do not handcraft replacements
- **Disclosure-profile mismatch:** stop export, correct the bounded reviewer
  population or redaction rule, and rerun
- **Investigation continuity gap:** stop export until event IDs,
  source-record IDs, and idempotency keys are all present again
- **Reviewer-package validation failure:** regenerate the population package
  from the same proof and inquiry artifacts; do not widen the schema
- **Owner ambiguity:** treat the workflow as not exportable until one reviewer
  owner and one support owner are explicit

---

## Support Boundary

Supported in `v2.47`:

- one reviewer-package family over internal, auditor, and counterparty review
- one bounded investigation package per reviewer population
- one fail-closed reviewer-owner and support-owner boundary

Not supported in `v2.47`:

- additional reviewer populations
- generic review portal or case-management product features
- additional downstream connectors or governance workflow breadth
- OEM packaging, embedded runtime ownership, or trust-network work
