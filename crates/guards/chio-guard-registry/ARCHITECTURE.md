# chio-guard-registry architecture

## Responsibility and boundary

This crate owns guard OCI references, transport, artifact packaging, local cache
layout, and verification admission orchestration. `GuardRegistryClient` publishes
and pulls artifacts; `GuardCache` stores them by digest. `GuardSigstoreVerifier`
wraps the shared `AttestVerifier` with an `ExpectedIdentity` chosen by the caller.
`load_guard_with_policy` evaluates cache integrity and signature reports for
online or offline loads. Guest execution and host-function capability enforcement
belong to `chio-wasm-guards`.

Registry repository names are distribution addresses. Signer annotations provide
metadata, and the expected signer identity is an explicit verifier input.
Neither a repository namespace nor marketplace metadata authorizes guest host
functions or agent tool calls. The runtime and kernel enforce those boundaries.

## Structure

- `oci` defines references, digest types, credentials, client configuration,
  artifact media types, descriptor validation, and Sigstore referrer discovery.
- `download` implements bounded OCI downloads with HTTP egress contracts.
- `publish` constructs OCI config and the ordered three-layer artifact, then
  sends it through the distribution client.
- `pull` obtains artifacts and optional bundles and writes validated cache data.
- `cache` defines digest-addressed paths and verifies stored artifact layout.
- `verify` maps attestation errors, reconciles signatures, and builds load events.
- `offline` checks completeness, integrity, and verification admission.
- `input` bounds file/JSON inputs and invokes duplicate-aware signed decoding.
- Feature-gated `marketplace` parses optional pricing and reputation metadata.

## Data and control flow

`GuardOciRef` parses an explicit `oci://` registry reference pinned by SHA-256.
`GuardPublishRef` accepts an explicit tag for publication. Publication constructs
layers in WIT, wasm module, guard manifest order, with role annotations and a
config descriptor carrying runtime metadata for `chio:guard/guard@0.2.0`.
Building the artifact serializes metadata and packaging; it does not execute or
cryptographically authenticate the supplied guest bytes.

Pulling retrieves the pinned manifest, validates descriptor media types, digests,
sizes, and ordered layers, then obtains a caller-supplied or OCI-referrer Sigstore
bundle. With both verifier and expected identity supplied, Sigstore verification
runs before the cache write. Supplying neither leaves `sigstore_verified` false;
supplying only one is rejected.

The cache contains `manifest.json`, `config.json`, `wit.bin`, `module.wasm`,
`guard-manifest.json`, and an optional `sigstore-bundle.json`. The offline policy
gate first requires the files needed for the selected verification mode, then
validates pinned artifact integrity, then calls the injected verifier closure.
Successful results contain a structured `chio.guard.verify` allow event;
failures retain explicit denial events and typed errors.

## Trust and invariants

Digest parsing requires 64 lowercase hexadecimal characters after `sha256:`.
Pull references require an explicit registry and reject tag-plus-digest inputs.
Artifact shape and cache checks bind retrieved bytes to pinned OCI descriptors.
The input layer bounds JSON to 16 MiB and artifact reads to 64 MiB; downloads
track an aggregate artifact budget and apply egress response limits.

`GuardSigstoreVerifier::verify_bundle` delegates certificate, expected identity,
artifact signature, and transparency metadata checks to `chio-attest-verify`.
It requires `rekor_inclusion_verified` for admission. Report-only APIs and
streamed detached verification may retain false inclusion metadata, so callers
must choose an admission API when activating a guard.

`verify_dual_mode` invokes both verifier closures even if one fails, requires
matching artifact digests and normalized signer identities, and requires verified
Rekor inclusion. Ed25519 verification itself is provided by the caller closure.
`GuardVerificationReport::admits_guard_load` applies the corresponding inclusion
rule to reports. The policy gate denies incomplete or tampered offline cache
entries before invoking the signature verifier.

## Dependencies

`oci-distribution` supplies reference parsing and publication transport.
Reqwest plus `chio-egress-contract` implement constrained HTTP retrieval.
`chio-core-types` provides strict JSON input decoding, SHA-256 binds descriptors,
and `chio-attest-verify` owns Sigstore cryptographic verification.
The optional `chio-reputation` dependency supplies marketplace reputation tiers.
Marketplace parsing exposes metadata without payment or policy activation.

## Verification

Run `cargo test -p chio-guard-registry` for reference parsing, layer ordering,
cache integrity, local verification failures, referrer retrieval, download limits,
and offline/dual-mode policy tests. `offline_and_dual_mode` checks tampered files,
unverified Rekor metadata, offline misses, and digest disagreement.
`cosign_verify_paths` tests shared-verifier error mappings and admission behavior.

Run `cargo test -p chio-guard-registry --features pq --test cosign_under_crypto_floor`
for the crypto-floor regression matrix. This feature does not make cosign payloads
hybrid signed. The ignored `zot_integration` test requires Docker and pulls the
Zot image; invoke it explicitly when those external prerequisites are available.
Local fixture tests and injected verifier tests establish their exercised
boundaries. Operators remain responsible for trusted identities and activation.
