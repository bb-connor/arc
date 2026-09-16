# Chio CMPv2 semantic repairs

This fork backports two RustCrypto repairs to the selected cmpv2 0.2.0 API.
The registry package is not certified by this local source selection.

- Original release commit: `ca08d8a11fc0b4cf3198adb14040f67ed29d5b0f`.
- Registry archive SHA-256:
  `961b955a666e25ee5a1091d219128d6e6401e3dab84efb1a2bf6b4035d797b39`.
- Failure-info repair:
  [`aeee92c272656127ad16c8636220dae40fb8868f`](https://github.com/RustCrypto/formats/commit/aeee92c272656127ad16c8636220dae40fb8868f).
- Poll-request repair:
  [`4f2771d6b309d002a6a02cca40aef08cb047a4bd`](https://github.com/RustCrypto/formats/commit/4f2771d6b309d002a6a02cca40aef08cb047a4bd).
- Poll-response repair:
  [`e4ffe7a57360b4bf1fcb3e162e2e06de193f662f`](https://github.com/RustCrypto/formats/commit/e4ffe7a57360b4bf1fcb3e162e2e06de193f662f).
- License: MIT OR Apache-2.0, original license texts retained.

The registry release declares ASN.1 bit positions as raw `flagset` values.
`flagset` requires each value to be a bit mask, so most variants encode as a
combination of unrelated low-order bits and higher failure bits cannot decode.
The upstream repair identifies the `BadTime` position and widens the backing
type to cover the complete specified range. Chio retains that widening and
maps all 27 specified positions to their required masks. The registry release
also models the context-specific poll-request body as `PollRepContent`; the
upstream repair uses the already defined `PollReqContent` type. Its polling
response omits the outer `SEQUENCE OF` and cannot represent multiple entries;
the upstream response repair restores that container.

Regression tests require every RFC failure-info mask and the DER value for the
`BadTime` bit, then decode, encode and inspect a tag 25 polling request. All
upstream tests, including the polling-response regression, remain present.
The manifest marks the fork unpublished and independently testable with Chio's
selected CRMF repair.

```sh
cargo test --locked --all-features --manifest-path third_party/cmpv2-chio/Cargo.toml
```
