# sigstore-rekor 0.6.6 source review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for the exact source, selected call sites and tested transport/encoding
boundaries. This is direct source review, not independent human certification.

Registry archive SHA-256:
`641fdaaa40d0cd6e249cf1671c2240beff1a3ece578062cf43e750779e8db2b3`.
Release source: `c9d76063833cb58a06483b181096294524d2dbf1`, under
`crates/sigstore-rekor` in prefix-dev/sigstore-rust.

## Scope and selected use

Reviewed both manifests, all five source modules, their three unit tests,
README and changelog. The crate has no unsafe code, build script or process
execution. It provides data models, explicit body decoding, request builders
and an asynchronous HTTP client. HTTP operations require explicit caller
invocation. Cryptographic dependencies do not make returned entries trusted.

Chio's resolved Rekor feature set is empty. The owned Sigstore verifier uses
`RekorEntryBody` in its HashedRekord and DSSE content-binding paths. It also
re-exports the crate publicly. No selected verification call site constructs
this crate's HTTP client. Chio's separate `chio-anchor::RekorClient` is a
different implementation and is outside this package audit.

Body decoding rejects malformed base64, invalid UTF-8, missing fields and
unsupported explicitly supplied kind/version pairs. PEM extraction checks
encoding. Certificate-chain validation, artifact digest equality, exact
signature/verifier equality, trusted time and authenticated log evidence are
performed separately by Chio's verifier. Its 44 library tests pass with this
registry package and the selected cryptographic repairs.

## Limits retained in the audit

- Parsed types and HTTP responses do not establish authenticity, inclusion,
  freshness, requested identity or index. V1 retrieval selects the first map
  entry without requiring its UUID/index to match the request. A localhost
  test confirms that an unrelated entry with no proof can be returned.
- V2 response conversion substitutes zero for invalid numeric strings,
  including time/index/proof fields. A localhost test records this behavior.
  Callers must not consume those values as verified evidence. Chio's selected
  verification path parses signed bundle data and performs separate checks;
  it does not use this HTTP conversion.
- V2 request constructors assume ECDSA P-256. Callers using other algorithms
  must not use those constructors without supplying the correct fields.
- A request's URL, identifiers and bodies come from callers. Identifiers are
  interpolated without URL-segment encoding. The client uses reqwest defaults
  for proxies, redirects and transport configuration and adds no operation
  timeout or response-size limit. It must not be used as an egress-policy
  boundary or as authorization for caller-selected URLs.
- Optional caches use fixed keys without repository namespacing. A cache must
  be isolated to one repository and trusted for its returned data. Cache errors
  fall back to HTTP, and successful deserialization is not authentication.
  The selected Chio feature graph does not enable this cache.
- Serde models accept additional fields and some semantically invalid values.
  In-toto payloads/signatures may need protocol-specific additional decoding.
  Input sizes and semantic/cryptographic validation remain caller obligations.

These limitations preclude treating this package as a log verifier. They do
not introduce a new accepted-authority path in Chio's audited use of its body
data models. Enabling HTTP/cache use in an authority decision requires review
of those caller obligations.

## Validation and conclusion

Three upstream unit tests, five retained boundary tests and two documentation
compilation checks pass with no default features and with all features. Two
upstream documentation examples remain ignored. The boundary tests exercise
invalid body/PEM encoding, HTTP error propagation and the untrusted response
behaviors above. Network tests use only a local loopback server; no artifact or
signature was submitted to a public log. These are not live service or TLS
qualification results.

Strict Clippy passes for all targets and features. All original production
source and test bytes remain unchanged. Validation adds standalone metadata,
selected crypto/Merkle patches, a lockfile and the retained audit test target.
The first offline attempt lacked the optional sigstore-cache index entry;
subsequent dependency fetching and both feature configurations completed.

The registry package receives a `safe-to-deploy` source audit with the explicit
data-model/transport boundary above. This does not certify its dependencies or
replace Chio's owned verification and complete workspace gates.

Evidence is retained in the primary checkout under
`output/process-security-20260915/sigstore-rekor-audit-25ab21af2/`. The added
boundary target is `sigstore-rekor-0.6.6-boundaries.rs` beside this report.
