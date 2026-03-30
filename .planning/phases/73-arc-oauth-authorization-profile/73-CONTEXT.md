# Phase 73: ARC OAuth Authorization Profile - Context

## Goal

Publish ARC's first normative enterprise-facing authorization profile that
maps governed intents and actions into legible OAuth-family authorization and
transaction-context semantics.

## Why This Phase Exists

ARC already has governed intents, authorization-details mapping, and call-chain
context, but the research asks for clearer enterprise IAM legibility. This
phase turns the existing substrate into one explicit profile rather than a set
of implementation details scattered across docs and code.

## Scope

- normative ARC authorization profile
- mapping of governed action semantics into authorization details and
  transaction context
- assurance, delegation, and bounded-rights language for IAM reviewers
- explicit fail-closed profile boundaries

## Out of Scope

- transport-specific sender-constrained mechanisms
- enterprise adapter packs and reviewer bundles
- conformance or qualification closure for the milestone
