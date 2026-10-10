# sigstore-tsa 0.6.6 source review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for the exact source and tested Chio trust boundary. This is direct source
review, not independent human certification or full RFC conformance testing.

Registry archive SHA-256:
`0bc86c8abc1ece6832236e7e34e9baebb5d4d40490c0332b814a0d8624ca7255`.
Release source: `c9d76063833cb58a06483b181096294524d2dbf1`, under
`crates/sigstore-tsa` in prefix-dev/sigstore-rust.

## Scope

Reviewed both manifests, all five source modules and their 15 unit tests, the
five retained timestamp/root fixtures, README and changelog. The crate has no
unsafe code, build script or process execution. It delegates DER handling to
RustCrypto types, cryptographic operations to AWS-LC and certificate-path
validation to rustls-webpki. Their audits remain separate.

The selected Chio feature set is empty. Chio uses offline timestamp verification;
it does not call this package's HTTP request client in the selected verifier.
The client hashes a caller-supplied signature, generates a random request nonce
and sends an explicit request to the caller's configured URL. It checks HTTP
and protocol response status, but does not bind the response nonce or verify
the returned timestamp. It adds no timeout, response-size or egress policy
beyond reqwest defaults. A successful request is not trusted-time evidence.

## Verification boundary

With nonempty explicit roots, verification checks SignedData/TSTInfo content
types, the message imprint against supplied signature bytes, the signed
message-digest attribute against TSTInfo, the CMS signature, and a certificate
path with timestamping EKU at the authenticated timestamp. Supported message
imprints are SHA-256/384/512. CMS signatures support P-256/SHA-256 and
P-384/SHA-256 or SHA-384; unsupported combinations reject.

Empty roots deliberately skip chain and EKU validation. This behavior is
explicitly exercised by an upstream test and by the retained boundary target.
`VerifyOpts::new()` alone therefore cannot establish trusted time. Providing
an embedded or out-of-band signer certificate is not equivalent to trusting
its issuer. Chio separately requires the verified signer to equal the leaf
certificate of a configured timestamp authority and checks that authority's
validity window. Its normal path supplies roots from that authority set.

A new Chio regression embeds the genuine signer certificate in a real CMS
token, confirms upstream signature-only verification succeeds, confirms Chio
accepts it with the configured authority, then removes the authority and
requires Chio to reject it. This exercises the authority check without relying
on the absence of an embedded signer certificate. The first fixture attempt
rejected earlier for a missing signer; that diagnostic and a corrected-import
compilation attempt are retained, not counted as final passes.

## Limits

- The first CMS signer and first matching signer certificate are selected;
  the API does not promise validation of every signer or an identity quorum.
- Signed attributes are re-encoded as DER SET OF for signature verification.
  The message-digest value is checked, but this implementation does not enforce
  all RFC 3161/CMS profile rules, such as every attribute's uniqueness,
  signing-certificate attributes, critical/exclusive timestamp EKU, policy
  selection, accuracy bounds or request/response nonce equality.
- Chain validation uses the token's authenticated time, not current time.
  It does not perform CRL/OCSP checks, enforce an operator freshness threshold
  or bind an authority's configured validity window. Chio supplies the latter
  check and its surrounding verification policy separately.
- Caller roots are trust inputs. Untrusted bytes must never populate them
  merely because a token contains those certificates. Data/input-size limits
  and trust-root authorization remain caller obligations.
- The request constructors use infallible convenience methods for allocation
  and ASN.1 encoding. Extremely large caller-owned inputs can exhaust memory
  or exceed DER length limits; these APIs are not resource isolation.

## Validation and conclusion

All 15 upstream unit tests pass with all features. Four added boundary tests
pass, covering valid evidence, invalid and unrelated real trust roots, changed
message imprint, signed timestamp/content substitution, signature substitution,
the explicit empty-root mode and canonical nonce extremes. Strict Clippy passes
for all targets/features. Chio's owned verifier passes all 45 library tests,
including the new authority-binding case. The fork's 37 restored upstream
integration cases also pass, both example targets compile, and its complete
all-target/all-feature Clippy gate passes after removing two needless test
borrows. Restored integration assertions are unchanged; only external fixture
include paths become local. No network service was contacted by these tests;
fixtures are retained release bytes.

All original production source, tests and fixtures remain unchanged. Standalone
validation adds metadata, selected crypto/CMP/CRMF dependency patches, a lockfile
and a separate audit test target. The registry package receives a
`safe-to-deploy` audit with the trust and profile boundaries above. This does
not certify signature-only mode as trusted-time verification or complete the
workspace, dependency-chain or runner acceptance gates.

Evidence is retained in the primary checkout under
`output/process-security-20260915/sigstore-tsa-audit-769f796a6/`. The boundary
target is `sigstore-tsa-0.6.6-boundaries.rs` beside this report.
