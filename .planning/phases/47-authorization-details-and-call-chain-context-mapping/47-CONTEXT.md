# Phase 47 Context

## Goal

Map governed intents and approvals into external authorization context
structures without silently widening identity, trust, or billing scope.

## Current Code Reality

- Governed intents already carry the canonical bounded action, purpose,
  optional spend ceiling, optional commerce context, optional metered-billing
  quote context, and optional runtime attestation.
- Approval tokens are already bound to the governed intent hash, which means
  any new delegated call-chain data added to the intent can automatically
  become approval-bound without changing the token format itself.
- ARC exposes remote OAuth-adjacent auth surfaces and local authorization
  endpoints, but it does not yet project governed receipts into
  standards-legible authorization-details or transaction-context structures.
- Receipt and report surfaces do not yet carry explicit delegated call-chain
  provenance for governed actions beyond generic capability lineage and child
  receipts.

## Decisions For This Phase

- Bind delegated call-chain context into the governed intent itself so the
  approval token continues to cover the full governed action through the intent
  hash.
- Keep external authorization context as a derived projection from signed
  governed receipt metadata rather than letting operators submit a second
  independently editable authorization document.
- Model the projection after OAuth RAR / transaction-context semantics:
  one or more authorization details plus a separate transaction/call-chain
  context block.
- Fail closed on malformed call-chain context and on self-referential upstream
  request bindings that would make provenance ambiguous.

## Risks

- If the exported authorization context can be edited independently from the
  signed receipt, ARC would silently widen authority through its reporting
  layer.
- If call-chain context is added only to reports and not to the governed
  intent, approval tokens will no longer cover the actual delegated context.
- If the mapping loses metered-billing or commerce ceilings, later IAM and
  underwriting layers will reason from incomplete economic scope.

## Phase 47 Execution Shape

- 47-01: add governed call-chain and authorization-context projection types
- 47-02: implement trust-control and CLI report surfaces for derived mappings
- 47-03: add fail-closed validation, docs, and regression coverage
