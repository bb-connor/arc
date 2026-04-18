# Swift API reference: `arc_kernel_mobile`

This document mirrors the UDL interface in
`crates/arc-kernel-mobile/src/arc_kernel_mobile.udl` one-to-one. It
is the contract `uniffi-bindgen generate --language swift` produces
and the contract the iOS app side should code against.

## Module

```swift
import arc_kernel_mobile
```

Package the module with a `.xcframework` that lipos
`libarc_kernel_mobile.a` across the iOS device and simulator slices
you ship for. See `bindings/README.md` for the full workflow.

## Functions

### `evaluate`

```swift
public func evaluate(requestJson: String) throws -> String
```

Evaluates a tool-call request against a capability token. The input
is a JSON object of shape:

```json
{
  "capability": <CapabilityToken JSON>,
  "trusted_issuers": ["<Ed25519 hex>"],
  "request": {
    "request_id": "req-1",
    "tool_name": "echo",
    "server_id": "srv-a",
    "agent_id": "<Ed25519 hex>",
    "arguments": { "..." }
  },
  "now_secs": 1700000100
}
```

`now_secs` is optional; values `<= 0` fall through to the device
wall-clock (`MobileClock`).

The return value is a JSON string:

```json
{
  "verdict": "allow" | "deny",
  "reason": "...",
  "matched_grant_index": 0
}
```

Errors (see `ArcMobileError` below) are only thrown when the inputs
themselves cannot be parsed; a kernel-core deny is encoded in the
JSON response so callers can render it without an exception path.

### `signReceipt`

```swift
public func signReceipt(bodyJson: String, signingSeedHex: String) throws -> String
```

Signs an `ArcReceiptBody` JSON with the 32-byte Ed25519 seed
(lowercase hex, optional `0x` prefix). The body's `kernel_key` must
equal the public key derived from `signingSeedHex`; otherwise the
function throws `ArcMobileError.kernelKeyMismatch(message:)`. Returns
the signed `ArcReceipt` as JSON.

### `verifyCapability`

```swift
public func verifyCapability(tokenJson: String, authorityPubHex: String) throws -> VerifiedCapability
```

Verifies a capability token against a trusted authority public key.
Uses the device wall-clock for the time-bound check; use
`evaluate()` with `now_secs` populated if you need a pinned clock.

### `verifyPassport`

```swift
public func verifyPassport(
    envelopeJson: String,
    issuerPubHex: String,
    nowSecs: Int64
) throws -> PortablePassportMetadata
```

Verifies a portable passport envelope (Phase 20.1 wire format). Pass
`nowSecs <= 0` to fall back to the device wall-clock.

## Records

### `VerifiedCapability`

```swift
public struct VerifiedCapability {
    public let id: String
    public let subjectHex: String
    public let issuerHex: String
    public let scopeJson: String
    public let issuedAt: UInt64
    public let expiresAt: UInt64
    public let evaluatedAt: UInt64
}
```

`scopeJson` is the canonical JSON encoding of `ArcScope`; decode it
with the app-side ARC SDK to inspect grants, constraints, etc.

### `PortablePassportMetadata`

```swift
public struct PortablePassportMetadata {
    public let subject: String
    public let issuerHex: String
    public let issuedAt: UInt64
    public let expiresAt: UInt64
    public let evaluatedAt: UInt64
    public let payloadCanonicalHex: String
}
```

`payloadCanonicalHex` is the lowercase-hex encoding of the authenticated
payload blob; decode with `Data(hexEncoded:)`.

## Errors

```swift
public enum ArcMobileError: Error {
    case invalidJson(message: String)
    case invalidHex(message: String)
    case invalidCapability(message: String)
    case invalidPassport(message: String)
    case kernelKeyMismatch(message: String)
    case signingFailed(message: String)
    case evaluationDenied(message: String)
    case `internal`(message: String)
}
```

Every variant carries a `message: String` describing the failure.
Render it directly via `error.localizedDescription` or a custom
`LocalizedError` adapter.

## Minimal usage

```swift
import arc_kernel_mobile

let requestJson = // ... built by your ARC SDK
let responseJson = try evaluate(requestJson: requestJson)

// Parse responseJson (e.g. with JSONDecoder) to read verdict / reason.
```

## Offline sync

See `bindings/README.md` for the offline evaluate + signReceipt +
queue + sync pattern the Phase 14.3 acceptance criterion calls out.
The FFI exposes primitives only; the queue, keystore, and sync layer
are owned by the app-side integration.
