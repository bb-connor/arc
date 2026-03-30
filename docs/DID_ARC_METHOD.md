# `did:arc` Method

**Status:** shipped in v2 portable-trust lane  
**Date:** 2026-03-23

**Transition note:** Phase 29 of the ARC rename freezes `did:arc` as a legacy
compatibility method for already-issued ARC artifacts. The planned ARC
transition is documented in
`docs/standards/ARC_IDENTITY_TRANSITION.md`.

---

## Overview

`did:arc` is ARC's currently shipped self-certifying DID method for Ed25519
identities already used by agents, kernels, and capability authorities.

Format:

```text
did:arc:{64-hex-character-ed25519-public-key}
```

Example:

```text
did:arc:80f2b577472e6662f46ac2e029f4b2d1300f889bc767b3de1f7b63a4c562fd8f
```

The DID is self-certifying. Basic resolution requires no registry lookup: the
method-specific identifier is the public key.

## Resolution

The resolver lives in the `arc-did` crate and is exposed in the CLI via:

```text
arc did resolve --did did:arc:...
arc did resolve --public-key <hex>
```

The resolved DID Document always contains:

- `@context: "https://www.w3.org/ns/did/v1"`
- one `verificationMethod` entry at `#key-1`
- `authentication` referencing `#key-1`
- `assertionMethod` referencing `#key-1`

The verification method shape is:

```json
{
  "id": "did:arc:...#key-1",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:arc:...",
  "publicKeyMultibase": "z..."
}
```

`publicKeyMultibase` is the base58btc encoding of the Ed25519 public key with
the standard multicodec prefix `0xed01`.

## Optional Services

Resolvers may attach receipt-log service endpoints when the local environment
knows where a subject's receipt log is published.

ARC currently ships one service type here:

- `ArcReceiptLogService`

CLI example:

```text
arc did resolve \
  --did did:arc:... \
  --receipt-log-url https://trust.example.com/v1/receipts
```

That produces a `service` entry like:

```json
{
  "id": "did:arc:...#receipt-log",
  "type": "ArcReceiptLogService",
  "serviceEndpoint": "https://trust.example.com/v1/receipts"
}
```

Multiple `--receipt-log-url` flags are allowed. They are emitted
deterministically as `#receipt-log`, `#receipt-log-2`, and so on.

## Current Boundary

Shipped now:

- self-certifying DID parsing and canonicalization
- DID document resolution for any ARC Ed25519 public key
- stable `Ed25519VerificationKey2020` verification method output
- optional receipt-log service attachment
- Agent Passport alpha verification on top of `did:arc`

Not shipped yet:

- `did:arc:update` receipt flows
- key rotation receipts
- external DID-method registration work
