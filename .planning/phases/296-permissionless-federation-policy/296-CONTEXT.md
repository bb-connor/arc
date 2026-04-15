# Phase 296 Context

## Goal

Operationalize permissionless federation admission in trust-control so
operators can publish bounded open-admission policies with explicit anti-sybil
controls and minimum-reputation gating.

## Constraints

- The contract layer already exists in `crates/arc-core/src/federation.rs`.
  Phase 296 must build on the signed
  `FederatedOpenAdmissionPolicyArtifact` surface instead of inventing a second
  federation policy family.
- The real runtime seam is `arc trust serve` in
  `crates/arc-cli/src/trust_control.rs`; the phase should extend that existing
  operator surface rather than creating a parallel daemon or out-of-band tool.
- The phase must stay bounded to roadmap requirements `DIST-03` and `DIST-04`:
  published open-admission policy, anti-sybil admission controls, and
  reputation-gated entry. It does not need to finish later phases about
  permissionless federation rollout or multi-region qualification.

## Findings

- Phase 139 already shipped the signed contract primitives:
  `FederatedOpenAdmissionPolicyArtifact`,
  `FederatedReputationClearingArtifact`, and `FederatedSybilControl`.
- Those artifacts are currently validated in `arc-core`, but they are not yet
  exposed as an operator-managed trust-control registry or admission-decision
  workflow.
- Trust-control already has a strong operator pattern for file-backed registries
  with both local CLI and shared HTTP control surfaces:
  enterprise providers, verifier policies, passport status, and
  certifications.
- Trust-control already exposes local reputation inspection through
  `issuance::inspect_local_reputation`, and that surface is the current bounded
  runtime source for effective score decisions.
- Phase 295 hardened clustered trust-control around a leader-backed write path,
  so new runtime admission decisions should stay on that service boundary.

## Implementation Direction

- Add one operator-managed registry that stores a signed federated
  open-admission policy plus trust-control runtime controls:
  rate limiting, proof-of-work difficulty, bond-backed requirement, and minimum
  reputation score.
- Expose that registry through the same local/remote operator workflow used by
  other trust-control registries:
  `arc trust federation-policy ...` and corresponding HTTP routes under
  `/v1/federation/...`.
- Add one admission evaluation endpoint that fail-closes on invalid signatures,
  unsupported admission class, insufficient reputation, missing proof-of-work,
  or exhausted rate-limit budget.
- Prove the phase through integration coverage that exercises:
  local CLI registry management,
  remote publication and health visibility,
  reputation-gated admission,
  proof-of-work enforcement,
  bond-backed enforcement,
  and rate-limit denial after repeated attempts.
