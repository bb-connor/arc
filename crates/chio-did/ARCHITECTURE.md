# chio-did Architecture

`chio-did` owns the self-certifying `did:chio` method. A DID is derived from the Ed25519 public key bytes used elsewhere in Chio, and resolution builds a DID Document without registry lookup.

The crate boundary is intentionally small: `DidChio` parses and renders canonical identifiers, `DidDocument` and `DidVerificationMethod` describe the resolved document, and `DidService` attaches resolver-provided service metadata such as receipt-log and passport-status endpoints.

The security constraint is that resolver metadata must not weaken the self-certifying identifier. Service URLs are public trust hints, so they must be syntactically valid and transport-safe before entering a DID Document.

Planned improvement: reject non-HTTPS service endpoints at construction time so receipt-log and passport-status services cannot advertise plaintext or local file endpoints.
