# CRMF 0.2.0 tag recursion and selected repair

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high in
the reproduced defect and repaired tag dispatch. This is a source review and
local validation, not an independent human certification.

## Provenance and finding

The registry archive SHA-256 is
`36fe21b96d5b87f5de4b5b7202ec41c00110ac817ce6728fe75fb2fe5962ed92`, matching
the previously selected lockfile. Its release source is RustCrypto/formats
commit `9023db5ddc882cc844d952ae7f74775f3aae797f`. All five production Rust
files and the published manifest were reviewed from checksum-verified bytes.

`EncKeyWithIdChoice::tag()` recursively calls itself for `GeneralName`, instead
of dispatching to the contained name. An ordinary DNS-name value reproduces a
stack-overflow process abort (signal 6) on Rust 1.94.1. The upstream test suite
passes its five tests and does not exercise this alternative.

RustCrypto already repaired this expression in
[commit 2f3e06651769300f8ffa2e04d887e4c8ab7ed16a](https://github.com/RustCrypto/formats/commit/2f3e06651769300f8ffa2e04d887e4c8ab7ed16a).
The selected compatible 0.2.0 registry release does not contain that repair.
This review does not establish a Chio runtime-input path to the affected method
and does not assert a new advisory or an upstream disclosure.

## Selected source and validation

The main, fuzz and generated Docker workspaces select
`third_party/crmf-chio`. The only production-code difference from the registry
archive is the upstream one-line delegation to `variant.tag()`. Each lockfile
changes only CRMF's registry source and checksum entry; versions and dependency
edges stay unchanged. Modified local bytes have explicit cargo-vet ownership,
not a certificate for the defective registry bytes.

The unpublished standalone fork retains the original license texts and tests.
Its controls test originally references a sibling CMS directory absent from the
published archive layout. The fork includes the exact CMS 0.2.3 fixture at a
self-contained path: SHA-256
`c1453aa0f250ea3db55e6181506a69196d6b144a061499de10268d30eeeda9ff`.

Validation on Rust 1.94.1:

- All seven tests pass with `cargo test --locked --all-features --no-fail-fast`:
  five retained upstream tests and two new regression tests. No tests ignored.
- Regression cases encode and decode DNS, email, URI, IP and directory names,
  check explicit primitive/constructed wire tags, preserve the UTF-8 alternative
  and reject an unrelated INTEGER tag.
- The original direct tag reproduction passes against the selected fork.
- Main and fuzz locked dependency metadata pass. Docker regeneration and its
  check pass. Workspace formatting and whitespace checks pass.
- Cargo-vet still fails with 21 unvetted registry dependencies. No criterion,
  exemption or imported trust authority was relaxed.

## Review boundary

CRMF supplies DER data models, not certificate issuance, signature verification
or authorization. Production source forbids unsafe Rust and has no build
script, network client, process execution or filesystem IO. DER parsing and
allocation are delegated to separately admitted dependencies. The manual choice
implementations were checked alongside their derive-based neighbors; the
repaired dispatch is the production change made here. Interoperability and
cryptographic verification remain caller responsibilities.

The original abort, archive inventory, upstream repair metadata and upstream
tests are retained in the primary checkout under
`output/process-security-20260915/asn1-dependency-audit-e271c26a6/`.
The actual graph, lockfile comparisons, selected-source reproduction and checks
are retained under `output/process-security-20260915/selected-crmf-validation/`.
This evidence does not replace Linux confinement qualification or the full
foundation gate on a final frozen candidate.
