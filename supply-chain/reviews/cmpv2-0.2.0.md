# cmpv2 0.2.0 selected repair review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
in the three reproduced wire defects and their selected repairs. This is direct
source review and validation, not independent human certification.

## Provenance and selection

- Registry archive SHA-256:
  `961b955a666e25ee5a1091d219128d6e6401e3dab84efb1a2bf6b4035d797b39`.
- Original release commit:
  `ca08d8a11fc0b4cf3198adb14040f67ed29d5b0f`.
- Reviewed all 1,181 original production lines, the normalized and source
  manifests, bundled fixtures and tests.
- The main, fuzz and generated Docker workspaces select
  `third_party/cmpv2-chio`, with Chio's selected CRMF repair beneath it.

The local package is unpublished. Cargo-vet treats it as owned source instead
of applying a registry certificate to different bytes. Its registry
dependencies remain subject to the normal deployment criteria.

## Repaired defects

The registry release declares all `PkiFailureInfoValues` as ASN.1 bit positions
inside `flagset::flags!`. That macro requires bit masks. `BadAlg = 0` therefore
represents no failure, numeric values such as 3 represent combinations of
lower bits, and failure positions above the low-order mask cannot decode. The
selected repair uses a `u32` backing value and maps all 27 RFC 4210 positions
to `1 << position`. Tests require every raw mask, round-trip every variant and
pin the DER encoding of `BadTime`.

The registry `PkiBody::PollReq` variant uses `PollRepContent`, so a conforming
tag 25 request cannot decode. RustCrypto fixed this in commit
`4f2771d6b309d002a6a02cca40aef08cb047a4bd`; the selected fork backports the
exact production change and tests the conforming DER request.

The registry `PollRepContent` models one response entry and omits the required
outer `SEQUENCE OF`, which also prevents representing multiple entries.
RustCrypto fixed this in commit
`e4ffe7a57360b4bf1fcb3e162e2e06de193f662f`; the selected fork backports the
production change and all three upstream regression tests.

## Review boundary

The crate is a `no_std` collection of DER data types. It forbids unsafe code,
has no build script and performs no filesystem, network, process or environment
access. Encoding and decoding delegate to the reviewed `der`, `x509-cert`,
`spki`, `cms` and selected `crmf` types.

This crate does not verify message protection, certificate chains, algorithms,
nonces, transaction continuity, proof of possession or policy. Callers must
perform those checks before trusting decoded fields. Size constraints described
by the RFC are not all represented as Rust constructors. The recursive tag 20
nested-message body remains disabled in this release, so this is not complete
CMP feature support. `ErrorMsgContent` can decode but its fields are private in
the selected API.

## Qualification

On the selected graph, all 31 tests pass: 26 retained release tests, two Chio
wire regressions and three upstream polling-response regressions. Strict Clippy
passes for all features and targets with warnings denied. Linux x86_64 terminal
results are retained under
`output/process-security-20260915/selected-cmpv2-validation/`.
