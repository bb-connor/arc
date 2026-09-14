# Release Evidence

This document is the external-reviewer entry point for Chio release evidence.
It is written for the crypto and protocol reviewer and the HITRUST i1 assessor.

## Checksum Index

For release `v<tag>`, fetch:

- GitHub Release assets from `https://github.com/backbay-labs/chio/releases/tag/v<tag>`
- Checksum index from `supply-chain/checksums/v<tag>.txt`
- Checksum index signature from `supply-chain/checksums/v<tag>.txt.sig`
- Checksum index certificate from `supply-chain/checksums/v<tag>.txt.pem`
- SLSA provenance asset `chio-<source_sha>.intoto.jsonl` from the same GitHub Release

The checksum index contains one row per release archive:

```text
<sha256>  <filename>
```

Verify downloaded artifacts with stock checksum tools:

```bash
sha256sum --check v<tag>.txt
```

On macOS without GNU coreutils:

```bash
shasum -a 256 -c v<tag>.txt
```

## Signature Verification

The checksum index is signed by the `release-binaries.yml` workflow using
keyless Sigstore signing. Verify it with:

```bash
cosign verify-blob \
  --certificate v<tag>.txt.pem \
  --signature v<tag>.txt.sig \
  v<tag>.txt
```

Use the certificate identity and issuer printed by `cosign verify-blob` to
confirm the signer is GitHub Actions for `backbay-labs/chio`.

## Rekor Witness

The checksum index header carries the SLSA provenance asset name:

```text
# slsa_provenance chio-<source_sha>.intoto.jsonl
```

After `.github/workflows/slsa.yml` publishes that asset, search
`https://search.sigstore.dev` for the provenance payload or the checksum-index
signature digest. Rekor is the transparency-log witness; the in-repo checksum
index is the stable reviewer index.

## Reproducibility Scope

`scripts/check-reproducible-build.sh` builds the `chio` binary twice from
clean archives of one commit in two separate directories, each with its own
path remapped away, and compares the results byte for byte:

```bash
scripts/check-reproducible-build.sh --rev HEAD --jobs 4 /tmp/chio-repro
```

It prints one `chio.reproducible-build.v1` JSON line with both digests and
exits nonzero when they differ. The first runs of this check found the binary
embedding its build checkout's absolute path through compile-time
`CARGO_MANIFEST_DIR` fallbacks, which path remapping does not touch; every
such fallback now resolves the checkout at runtime from the executable's
location, and with that change in place two builds on aarch64-unknown-linux-gnu
with the pinned toolchain were byte-identical, sha256
`db2462d608774014732b77c930c06f2a5558c68ce8f2f3c2511b8cc02e09a7c1`. That
run is the evidence for this platform; the release pipeline's own rebuild
is what establishes it for a published artifact.

The release pipeline guarantees Linux x86_64 reproducibility for the `chio`
binary. macOS and Windows release archives are still checksum-published and
signed, but they are not claimed to be byte-reproducible because codesign and
PE timestamp behavior remains platform-dependent.
