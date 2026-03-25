# PACT Receipts Profile

## Purpose

This document is the standards-submission draft for PACT receipts as shipped in
this repository.

It defines the interoperable core for signed mediation evidence, not every
possible deployment, analytics, or compliance extension.

## Scope

The profile covers:

- `PactReceipt`
- `ChildRequestReceipt`
- checkpoint statements
- receipt verification and failure semantics
- compatibility expectations for additive metadata

The profile does not cover:

- public log gossip or witness networks
- multi-region consensus replication
- downstream SIEM schemas
- organization-specific billing or settlement payloads

## Terminology

| Term | Meaning |
| --- | --- |
| capability | Signed authorization presented for a mediated action |
| receipt | Signed record of a mediated decision |
| child receipt | Signed record of a nested sub-operation under a parent request |
| checkpoint | Signed Merkle commitment over a receipt batch |
| fail closed | Reject the action or artifact instead of widening access |

## Normative Artifact

The receipt envelope is the signed `PactReceipt` body plus signature:

- `id`
- `timestamp`
- `capability_id`
- `tool_server`
- `tool_name`
- `action`
- `decision`
- `content_hash`
- `policy_hash`
- `evidence`
- optional `metadata`
- `kernel_key`
- `signature`

`decision` is one of:

- `allow`
- `deny`
- `cancelled`
- `incomplete`

Implementations must preserve those distinct terminal states.

## Security Properties

- the signature covers the canonical JSON body
- the verifying key is embedded as `kernel_key`
- the action payload is hashed as `parameter_hash`
- the evaluated outcome is hashed as `content_hash`
- guard evidence remains operator-visible
- receipt verification is independent of transport

## Compatibility Rules

- additive metadata is allowed
- unknown top-level receipt fields must not invalidate an otherwise valid
  signature check if canonical verification succeeds
- unknown checkpoint schema identifiers must be rejected
- consumers must not reinterpret `cancelled` or `incomplete` as `allow`

## Non-Goals

- cross-vendor guarantee of identical metadata schemas beyond the signed core
- standardization of every analytics or export view built on receipts
- standardization of deployment topology for receipt storage
