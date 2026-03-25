# `did:pact` Method

**Status:** shipped in v2 portable-trust lane  
**Date:** 2026-03-23

---

## Overview

`did:pact` is PACT's self-certifying DID method for Ed25519 identities already
used by agents, kernels, and capability authorities.

Format:

```text
did:pact:{64-hex-character-ed25519-public-key}
```

Example:

```text
did:pact:80f2b577472e6662f46ac2e029f4b2d1300f889bc767b3de1f7b63a4c562fd8f
```

The DID is self-certifying. Basic resolution requires no registry lookup: the
method-specific identifier is the public key.

## Resolution

The resolver lives in the `pact-did` crate and is exposed in the CLI via:

```text
pact did resolve --did did:pact:...
pact did resolve --public-key <hex>
```

The resolved DID Document always contains:

- `@context: "https://www.w3.org/ns/did/v1"`
- one `verificationMethod` entry at `#key-1`
- `authentication` referencing `#key-1`
- `assertionMethod` referencing `#key-1`

The verification method shape is:

```json
{
  "id": "did:pact:...#key-1",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:pact:...",
  "publicKeyMultibase": "z..."
}
```

`publicKeyMultibase` is the base58btc encoding of the Ed25519 public key with
the standard multicodec prefix `0xed01`.

## Optional Services

Resolvers may attach receipt-log service endpoints when the local environment
knows where a subject's receipt log is published.

PACT currently defines one service type:

- `PactReceiptLogService`

CLI example:

```text
pact did resolve \
  --did did:pact:... \
  --receipt-log-url https://trust.example.com/v1/receipts
```

That produces a `service` entry like:

```json
{
  "id": "did:pact:...#receipt-log",
  "type": "PactReceiptLogService",
  "serviceEndpoint": "https://trust.example.com/v1/receipts"
}
```

Multiple `--receipt-log-url` flags are allowed. They are emitted
deterministically as `#receipt-log`, `#receipt-log-2`, and so on.

## Current Boundary

Shipped now:

- self-certifying DID parsing and canonicalization
- DID document resolution for any PACT Ed25519 public key
- stable `Ed25519VerificationKey2020` verification method output
- optional receipt-log service attachment
- Agent Passport alpha verification on top of `did:pact`

Not shipped yet:

- `did:pact:update` receipt flows
- key rotation receipts
- external DID-method registration work
