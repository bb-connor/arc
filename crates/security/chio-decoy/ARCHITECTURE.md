# chio-decoy architecture

## Responsibility and boundary

The crate owns deception-record lifecycle validation, sealed registry
coordination, owned-file publication and cleanup, and marker detection.
`PrivateDecoyRegistry` connects a `SealedDecoyRegistryStore`, a key provider,
and an export authorizer. `DecoyDetector` converts a marker presentation into
an active match, inactive observation, or clear result.

Registry and detector objects neither install an ingress guard nor dispatch a
quarantine response. Embedding code consumes `requires_immediate_deny` and
evidence references. An active match is a detection signal with
`malice_proven: false`, including operator and scanner observations.

## Structure

- `lifecycle.rs` implements transition, failure, exact retry, and
  `ArmedReplacement` checks against records from `chio-security-types`.
- `registry.rs` owns encrypted private envelopes, HMAC lookup tokens,
  key-version overlap, compare-and-swap coordination, and privileged export.
- `materialize.rs` owns filesystem identity, path checks, ownership proofs,
  staging locks, publication, and quarantine-before-removal cleanup.
- `matcher.rs` implements observation validation and detection classifications.
- `watermark.rs` implements issuance, canonical token encoding, verification,
  candidate advisories, and observation persistence results.

## Data and control flow

`PrivateDecoyRegistry::create` checks artifact and marker uniqueness, validates
predecessor links, creates the initial lifecycle record, encrypts its private
envelope, and submits a sealed compare-and-swap request. Exact operation retries
recover the existing record only when the request still matches. Returned sealed
state must match the proposed state.

The initial lifecycle state advances through `Materializing`, `Armed`,
`Triggered`, `Rotating`, and `Retired`. Errors retain the prior state and
attempted operation.
Recovery permits an exact recorded retry or retirement. Normal rotation
retirement requires a distinct successor with matching tenant, surface, scope,
predecessor linkage, next version, and a matchable lifecycle: `Armed`,
`Triggered`, or `Rotating`.

`materialize_file` coordinates the registry with `FileMaterializer`. The latter
opens a root descriptor and walks relative paths with no-follow operations.
A staging directory lock serializes independent instances. Publication uses a
no-replace rename and synchronizes directories. Cleanup validates the receipt
and ownership proof, moves the file into a quarantine directory, verifies it
again, and removes that owned entry. Exact retries validate existing content.

`WatermarkIssuer::issue` resolves a verified source context, checks clock and key
policy, requires an unexpired matchable registry marker, and reserves its sequence
before signing. `WatermarkVerifier::scan_text` finds bounded candidates, verifies each,
resolves registry state, and records attribution through an observation store.
Observation-store failure remains explicit even when a verified active hit exists.

## Trust and invariants

Registry keys and secret material use zeroizing containers and redact debug
output. ChaCha20-Poly1305 authenticates the private envelope; domain-separated
HMAC indexes bind tenant and lookup purpose. Key versions select the active key
or a bounded set of retired keys whose overlap windows permit reads.

`transition` checks generation, version, operation shape, and legal state edges.
`DecoyDetector::detect` rejects empty or zero-time observations and distinguishes
registry availability, integrity, and lifecycle failures from a clear lookup.
Only direct presentation sets the immediate-denial flag for an active match.

Watermarks bind tenant, application, session, receipt, tool, sequence, marker,
key, and time window. Canonical base64url JSON and signature checks precede
acceptance. Scanning is bounded to 4 MiB of text and 32 candidates; individual
envelopes have a 16 KiB encoded-size limit. Malformed candidates remain advisory.

The store trait owns transaction atomicity and durability for sealed registry
updates. Sequence and observation stores own their persistence contracts.
File materialization requires Unix, working locks, extended attributes, and
supported no-replace rename behavior. Non-Unix entrypoints return `Unsupported`.
Apple directory custody also rejects extended ACL authority.

## Dependencies

`chio-security-types` supplies lifecycle and persistence contracts.
`chio-core-types` supplies canonical JSON and signing interfaces.
`chacha20poly1305`, `hmac`, `sha2`, `rand_core`, and `zeroize` support envelope
custody. `rustix` provides descriptor operations and filesystem locking;
`chio-file-custody` supplies Apple ACL checks. `base64` encodes watermarks.

## Verification

Integration tests cover legal and illegal lifecycle edges, sealed-row privacy,
tenant separation, concurrent CAS, key overlap, materializer cleanup and retry,
watermark replay, malformed candidates, and observation-store failures.
Materializer concurrency tests exercise simultaneous publication; Apple ACL
fixtures are platform gated. Run `cargo test -p chio-decoy` on the target host.
The README uses the pure `transition` API and creates no registry or file.

[README](README.md) | [Trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
