# sigstore-crypto 0.6.6 review and prehashed verification repair

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for the reproduced defect and repaired signature behavior. This is direct
source review, not independent human certification.

## Exact source and review

Registry archive SHA-256:
`da90c3d9af638898a5fdc347479b18f950bb0dde11ecf2244f94cd28135da53b`.
The archive identifies prefix-dev/sigstore-rust release
`c9d76063833cb58a06483b181096294524d2dbf1`, under `crates/sigstore-crypto`.
Reviewed both manifests and all eight source modules, including their tests.

The package wraps AWS-LC key generation, signing, hashing and verification;
parses SPKI, certificate and checkpoint data; and provides a caller-populated
keyring. It has no unsafe Rust, build script, network client, process execution
or filesystem opening. Its streaming hash reads a caller-supplied `Read`, and
key generation/signing use the backend's system RNG. Backend and ASN.1
dependencies require their own audits.

## Reproduced defect

The registry implementation of `verify_prehashed` handles ECDSA P-256 using a
backend digest-verification API. Its other branches instead pass the SHA-256
digest bytes to ordinary message verification. For RSA, that hashes the digest
again and verifies a signature over a different message.

The retained reproduction generates an ephemeral RSA-2048 key locally and
checks both RSA PKCS#1 v1.5 SHA-256 and RSA-PSS SHA-256. For each scheme:

- A signature over the artifact passes ordinary verification but fails the
  original prehashed API given the artifact's correct SHA-256 digest.
- A signature over those 32 digest bytes fails ordinary verification against
  the artifact but passes that same original prehashed API.

No external service or user key participates. This establishes a cryptographic
API semantics defect. It is not evidence of an observed attack or a complete
Chio bundle bypass: bundle trust, time, certificate and log binding still apply.
The owned verifier's digest branch does call this API for supported SHA-256
schemes, so the dependency boundary must be repaired rather than certified.

## Selected correction

`third_party/sigstore-crypto-chio` adapts the relevant correction from upstream
[commit 267dacdb172e590c2081c1480a8c5a0555e89b2a](https://github.com/prefix-dev/sigstore-rust/commit/267dacdb172e590c2081c1480a8c5a0555e89b2a).
The compatible API still takes a fixed-size SHA-256 digest. ECDSA P-256,
RSA PKCS#1 v1.5 SHA-256 and RSA-PSS SHA-256 now use `verify_digest` with the
imported digest. Ed25519 and schemes requiring longer hashes return
`UnsupportedAlgorithm`; the upstream API expansion to additional digest types
is not included.

The sole production-file diff is `src/verification.rs`. The main, fuzz and
generated Docker graphs retain the same package version and dependencies and
select the unpublished owned fork. AWS-LC remains at the previously selected
1.18.1/0.45.0 versions. Cargo-vet explicitly treats the fork as owned source;
the original registry source receives no audit or exemption.

## Validation and limits

All 14 upstream unit tests, four new regression tests and one documentation
compile test pass. The RSA test now accepts artifact signatures and rejects
signatures over digest bytes. Further cases preserve ECDSA binding, reject a
valid Ed25519 signature over digest bytes, and reject all six schemes requiring
SHA-384/SHA-512 through this SHA-256-only API. Strict Clippy passes for all
targets and features with warnings denied.

All 42 library tests of Chio's owned Sigstore verifier also pass with the
repaired crypto and Merkle packages selected. This covers the existing identity,
time, log, content and signature regressions as a composed library target.

Certificate parsing extracts claims; it does not authenticate a certificate
chain, identity, issuer or trust period. Explicit verification schemes and
trusted keyring membership remain caller inputs. Checkpoint verification is
over the preserved signed note; caller mutation or JSON reconstruction of its
public fields is not a new signed claim. No FIPS validation or final frozen
integration qualification is inferred from these focused tests.

The original archive, red reproduction, upstream repair metadata, sole
production-file diff, selected source hashes, resolved graphs and full test/lint
logs are retained in the primary checkout under
`output/process-security-20260915/sigstore-crypto-audit-7ff6ba3bd/`.
