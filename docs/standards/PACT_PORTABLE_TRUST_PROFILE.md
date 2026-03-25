# PACT Portable Trust Profile

## Purpose

This document is the standards-submission draft for PACT portable trust as
currently shipped.

It defines the interoperable artifact layer for self-certifying identity,
portable reputation credentials, verifier policies, challenge/response
presentation, and federated evidence handoff.

## Scope

The profile covers:

- `did:pact`
- `pact.agent-passport.v1`
- `pact.passport-verifier-policy.v1`
- `pact.agent-passport-presentation-challenge.v1`
- `pact.agent-passport-presentation-response.v1`
- `pact.evidence_export_manifest.v1`
- `pact.federation-policy.v1`
- `pact.federated-delegation-policy.v1`

The profile does not cover:

- a global trust registry
- public wallet/discovery distribution
- synthetic cross-issuer trust scoring
- automatic enterprise identity propagation into every artifact

## Terminology

| Term | Meaning |
| --- | --- |
| `did:pact` | Self-certifying Ed25519 DID method |
| passport | Bundle of one or more signed reputation credentials for one subject |
| verifier policy | Signed relying-party policy artifact |
| presentation challenge | Signed verifier challenge for replay-safe presentation |
| presentation response | Signed subject response carrying a filtered passport presentation |
| federation policy | Signed bilateral policy governing evidence export/import scope |
| delegation policy | Signed ceiling for federated continuation from imported upstream capability context |

## Normative Claims

- `did:pact` method-specific identifiers are lowercase hex Ed25519 public keys
- every passport credential binds issuer and subject as `did:pact`
- multi-issuer passport bundles are valid only when all credentials name the
  same subject and verify independently
- verifier acceptance is per credential; no synthetic aggregate issuer or score
  is invented
- challenge/response verification must reject replay and invalid verifier
  policy bindings
- evidence-export and delegation artifacts must carry explicit signed policy
  material rather than implicit trust assumptions

## Compatibility Rules

- unknown schema identifiers must be rejected
- additive fields are allowed where signature verification still succeeds
- consumers must not invent cross-issuer trust semantics not present in the
  artifact contract
- imported evidence must remain distinguishable from native local receipts in
  reporting and analytics

## Non-Goals

- public portability marketplace or wallet network
- standardization of reputation scoring formulas across issuers
- automatic federation of all enterprise identity metadata
- guarantee that every verifier shares the same policy thresholds
