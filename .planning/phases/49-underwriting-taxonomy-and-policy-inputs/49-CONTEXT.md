# Phase 49 Context

## Goal

Define the signed underwriting policy-input contract and canonical risk
taxonomy over ARC's existing evidence surfaces.

## Current Code Reality

- ARC already exports canonical evidence across receipts, governed approvals,
  metered-cost reconciliation, certification, reputation, and runtime
  assurance, but those surfaces are still consumed independently rather than
  through one underwriting contract.
- `spec/PROTOCOL.md` still treats the signed behavioral feed as a truthful
  evidence export rather than an underwriting decision surface.
- Existing operator tooling can query evidence, but it does not yet define a
  bounded taxonomy of risk classes, reasons, or policy inputs that later
  decision logic can rely on.
- The economic-interop work in `v2.9` means ARC now has standards-legible
  cost and authorization context that underwriting can reference without
  inventing a second pricing vocabulary.

## Decisions For This Phase

- Define underwriting inputs as signed or signable evidence snapshots over
  canonical ARC truth rather than as free-form partner JSON.
- Keep underwriting policy truth separate from execution receipts, just as
  ARC already separates execution truth from settlement and metered-cost
  evidence.
- Use explicit risk classes, decision reasons, and evidence references so
  later evaluation and appeals can explain outcomes precisely.
- Fail closed when required evidence is missing, stale, or contradictory.

## Risks

- If the taxonomy is too vague, the runtime decision engine will collapse into
  opaque partner-specific logic and break the research goal.
- If underwriting inputs duplicate receipt or reputation data by value without
  provenance, ARC will create a second mutable truth source.
- If validation is permissive, later premium or ceiling decisions can appear
  deterministic while actually depending on incomplete evidence.

## Phase 49 Execution Shape

- 49-01: define underwriting taxonomy, evidence references, and policy-input
  contracts
- 49-02: thread underwriting input assembly and query surfaces through kernel,
  store, and operator APIs
- 49-03: add docs, validation, and regression coverage for fail-closed input
  handling
