# Phase 297 Context

## Goal

Add a bounded SCIM 2.0 lifecycle seam so external IdPs can provision and
deprovision ARC enterprise identities through trust-control without inventing a
second identity control plane.

## Constraints

- The repo already ships enterprise provider administration in
  `crates/arc-cli/src/enterprise_federation.rs` and enterprise-provider
  admission in `crates/arc-cli/src/trust_control.rs`. Phase 297 must extend
  those seams instead of creating a separate identity service.
- The phase is scoped to roadmap requirements `DIST-05` and `DIST-06`:
  `POST /Users` provisioning and `DELETE /Users/{id}` deprovisioning. It does
  not need to implement a full generic SCIM server, PATCH semantics, reusable
  IdP sync orchestration, or broad IAM management workflows.
- Deprovisioning must have real security value. A registry that only stores a
  user record but does not affect capability issuance or revocation would be
  incomplete.

## Findings

- `docs/IDENTITY_FEDERATION_GUIDE.md` already documents `scim` provider records
  but explicitly states that automatic SCIM provisioning lifecycle is not yet
  implemented.
- Trust-control already owns the bounded operator seams needed for this phase:
  enterprise provider validation, capability issuance, capability revocation,
  receipt persistence, and cluster-aware leader forwarding for writes.
- `federated_issue` already enforces enterprise-provider admission with a
  validated provider-admin record and is the right place to fail closed for
  inactive SCIM identities.
- Capability lineage is keyed by issued capability IDs and subject public keys,
  not by enterprise `subject_key`, so SCIM deprovisioning needs its own mapping
  from enterprise identity to capability IDs issued through the SCIM-governed
  lane.

## Implementation Direction

- Add one file-backed SCIM lifecycle registry that stores:
  a SCIM user resource,
  the derived ARC enterprise identity context,
  tracked capability IDs issued under that identity,
  and deprovisioning metadata.
- Expose a SCIM-shaped trust-control surface under `/scim/v2/Users` that:
  validates the referenced provider against the provider-admin registry,
  computes the ARC enterprise identity,
  persists the provisioned user record,
  and returns a SCIM user resource with ARC extension metadata.
- Extend `federated_issue` so that when a validated `scim` provider is active
  and the lifecycle registry is configured, issuance requires a matching active
  SCIM identity and records newly issued capability IDs back onto that identity.
- On delete, mark the SCIM identity inactive, revoke every still-active
  capability tracked for that identity, append a signed deprovisioning receipt,
  and make later federated issuance fail closed for that identity.
- Prove the phase with black-box trust-control tests for SCIM provision and
  delete flows plus a federated-issue regression showing that deprovisioned
  SCIM identities cannot receive new capabilities.
