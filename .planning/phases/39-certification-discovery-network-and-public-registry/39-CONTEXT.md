# Phase 39 Context

## Goal

Turn certification into a multi-operator discovery surface instead of a purely
local artifact store.

## Current Code Reality

- ARC already supports certification publication, resolution, supersession, and
  revocation through local and remote registry flows.
- Those flows are still operator-scoped. They prove the certification artifact
  shape, but not yet the broader discovery-network semantics needed for a
  public or federated registry story.
- Portable trust and identity provenance work from phases 37-38 will make
  remote certifications safer to reason about, but the registry still needs a
  real multi-operator query and trust model.
- Later launch work needs a credible story for "how does a partner discover an
  ARC certification and know whether it is current?"

## Decisions For This Phase

- Treat discovery as a registry contract with provenance, revocation, and
  supersession semantics, not as a best-effort search index.
- Keep operator boundaries explicit: discovery can cross organizations, but it
  should not collapse issuer ownership into a global mutable store.
- Reuse existing certification artifact families where possible instead of
  inventing separate "public registry only" objects.
- Make discovery and publication flows operator-visible through CLI and
  trust-control rather than bespoke one-off scripts.

## Risks

- Multi-operator publication can produce stale or conflicting indexes if
  supersession rules are not explicit.
- Public discovery can overstate trust if the registry contract is looser than
  the certification artifact contract.
- CLI and trust-control could diverge on discovery semantics if both grow
  separate query paths.

## Phase 39 Execution Shape

- 39-01: define the discovery-network and public-registry contract
- 39-02: implement multi-operator publication and query surfaces
- 39-03: add docs and regression coverage for discovery flows
