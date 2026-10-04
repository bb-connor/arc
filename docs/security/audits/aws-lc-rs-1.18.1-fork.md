# AWS-LC Rust source audit and fork acceptance

Date: 2026-10-04. Reviewers: Codex implementing source reviewer and a separate
Codex source-review agent. This is a source audit of the identified package and
fork. It is not an upstream maintainer endorsement, FIPS certification, hosted
PR qualification, or approval to publish a release.

## Judgment and exact source

The published `aws-lc-rs 1.18.1` archive does not meet `safe-to-deploy` on this
review. It contains DES key-validation defects and a confirmed Rust memory-
initialization defect in safe AES cipher/key-wrap APIs. A private diagnostic
also violates an unsafe C-string constructor's precondition. Do not create an
unconditional deployment audit for that registry version.

The corrected Chio fork is accepted for the deployment feature set enforced by
`scripts/check-aws-lc-fork.py`, subject to the native dependency audits, locked
resolution, and exact source inventory in `supply-chain/aws-lc-rs-fork.json`.
The review covers both default AWS-LC and FIPS wrapper paths. Optional legacy
DES is repaired and regression-tested but remains excluded from deployment
resolution. Test-only, unstable, and sanitizer features likewise require a
separate deployment-policy decision.

- Registry archive SHA-256:
  `b281d307588d634de920874890732659e2e7672f72b5e10e81badc1a8a83621e`.
- Published VCS identity: `22e629d5c46276497a24ee3e575be4315940e7cb`.
- Upstream source archive SHA-256:
  `43390fa01fc30a32873a6851bd1f5eda94443ae29e70f0272bfb3d47a3aeaadc`.
- Native versions: `aws-lc-sys 0.45.0`, `aws-lc-fips-sys 0.14.2`.
  Their separate source audits are retained in `supply-chain/audits.toml`.
- The full fork is reproducible from the authenticated registry archive, the
  ASCII-encoded `CHIO-PATCH.patch.json`, and 71 fixtures from the upstream
  commit. Eight fixtures receive only documented whitespace normalization.

The inventory includes the crate manifest, build script, all Rust files, test
data, standalone lock, and provenance metadata. An added, removed, modified or
symlinked input fails the gate. Source changes require a new review and inventory;
regenerating hashes is not an audit.

## Joined source-review coverage

The earlier retained audit inspected build.rs, the owning/borrowed pointer and
buffer abstractions, native allocation ownership, RNG, constant-time comparison,
CBB/BN helpers, digest, HMAC/HKDF/PBKDF2, AEAD algorithms and contexts, nonce
sequences and counters, TLS/QUIC/Poly1305/OpenSSH, and symmetric block/padded/
streaming cipher implementations. Native sys archive provenance, build selection,
compiler/bindgen argument vectors, FIPS startup checks, AES-GCM limits and EVP
output capacities were reviewed separately. Its retained read views and progress
record are under the archived roadmap's `output/process-security-20260915/
resume-20260921/aws-lc/`; these earlier results are historical evidence.

The implementing reviewer additionally read the full production definitions in
`ec.rs`, `ec/{encoding,key_pair,signature}.rs`, `ed25519.rs`, `rsa/{key,encoding,
signature,encryption}.rs`, `rsa/encryption/{oaep,pkcs1}.rs`, `kem.rs`, `pqdsa.rs`,
`pqdsa/{key_pair,signature}.rs`, `agreement.rs` and `agreement/ephemeral.rs`.
The review traced algorithm allowlists, key/curve binding, ownership transfer,
fallible native return handling, capacity/output-length contracts, parser
contracts, sign/verify padding, ephemeral consumption and shared-secret owners.

The [independent review](aws-lc-rs-1.18.1-independent-review.md) records exact
production line coverage for CMAC, key wrapping, TLS PRF/KDF, signature factories,
EVP ownership/refcounts/parsers, DER/encoding/endian helpers, feature/init wrappers
and every aggregate `MaybeUninit` site. It separates its own source reads from
earlier evidence and independently reviews the implemented repairs. Its native
checks cover both sys/FIPS contracts, including thread-safe nonmutating EVP
operations, saturating reference counts, KEM/PQDSA export sizes and cleansing.

This is a security source audit, not an independent proof of every cryptographic
algorithm or a rereview of all native assembly. The native implementation is a
separate dependency with its own retained audit and upstream source identity.

## Findings and repairs

| Finding | Evidence | Repair |
| --- | --- | --- |
| AES-128/192 native setup leaves unused integer fields untouched; safe Rust assumed a fully initialized AES_KEY | Both native backends, binding field definitions, and native Memcheck reproduction | Zero-initialize all six AES_KEY allocations before native setup; preserve native return checks |
| DES weak/semi-weak parity variants and parity-distinct equal TDEA components were accepted | Retained failing registry regression, native key-validation contract | Normalize odd parity, reject every nonzero native key-setup result, compare effective keys ignoring parity |
| Private diagnostic interpreted a whole zero-filled buffer as a single unchecked C string | Native termination contract and the Rust constructor's interior-NUL precondition | Use bounded safe `CStr::from_bytes_until_nul` |

The AES repair leaves the native algorithm's used schedule words unchanged. The
new test reads the unused words of encryption and decryption schedules for both
AES-128 and AES-192. On native Linux x86_64 with Rust 1.94.1, the original
allocations produced Memcheck exit 97 with 48 uninitialized conditional errors
from two contexts. The same test after the repair returned zero and reported zero
errors. Both logs are retained:
[original](aws-lc-aes-memcheck-red.log.gz),
[repaired](aws-lc-aes-memcheck-green.log.gz).
The harness's reported reachable/possibly-lost allocations are not relabeled as
a leak-free whole-process qualification.

The corrected native fork also passed 386 library tests with `legacy-des`, all
three DES regressions, 36 doctests with one ignored, and 491 FIPS library tests.
These source tests used the retained native x86_64 qualification worker; they
do not constitute the later exact landing candidate's hosted/native qualification.

## Audit enforcement

Cargo Vet's path-dependency audits apply to the original published crate, not
the local fork. This makes a registry `safe-to-deploy` entry incorrect here.
See [Cargo Vet's source identity rules](https://mozilla.github.io/cargo-vet/first-party-code.html).

The local `aws-lc-upstream-reviewed` criterion records the genuine upstream
source review and its known defects. It has no implied criteria and does not
approve deployment. `audit-as-crates-io = true` remains enforced. Each direct
native/transitive dependency retains the standard `safe-to-deploy` requirement.
No new exemption is introduced for the fork or its native dependencies.

The mandatory combined command is `bash scripts/check-supply-chain.sh`. Both
required Cargo Vet jobs and release/hosted qualification call that command.
Rust binary, sidecar, C++ and npm/Wasm release producers also require the shared
Cargo Vet workflow at their immutable event commit before building or publishing.
The reusable workflow uses a caller-specific concurrency group, so another
publisher cannot cancel its prerequisite. It
requires the complete fork source inventory and audit report, authenticated
archive reconstruction, actual locked Cargo metadata for the root, fuzz, Lambda,
verdict matrix and reduced Docker workspaces, the Cargo Vet audit graph, and the
DES/AES regressions. Registry/path substitution, a second AWS-LC Rust copy, and
features outside the reviewed deployment set are rejected. Cargo Vet by itself
is only the upstream-review/transitive-audit portion of this combined gate.

The unit mutation controls exercise changed, omitted, added and symlinked source,
registry and alternate-path substitution, duplicate AWS-LC copies and unreviewed
features. Independent PR review must additionally verify the required workflow
wiring; candidate-owned scripts cannot attest their own trusted execution.
The workflow mutation checks reject missing and conditional prerequisites and
mutable C++ archive identities. C++ registry ports retain the qualified source
repository and commit, rather than resolving a release tag again. A
repeat-run regression verifies that Cargo outputs stay outside the audited fork;
the default output is `target/aws-lc-audit`, and an explicitly supplied target is
preserved. Two actual consecutive combined invocations with an initially unset
`CARGO_TARGET_DIR` passed without changing the source inventory.

## Limits and remaining hardening

Successful key parsing is not a promise of exact whole-input DER consumption;
some native parsers are streaming parsers. Applications needing canonical
whole-input identity must enforce it separately. Key-wrap callers must ignore
their output buffer on authentication failure; the API returns Err but does not
promise clearing those bytes. Raw/legacy ciphers provide no authentication.

The review found no blanket zeroization guarantee for every copy or temporary:
Ed25519 seed storage, CMAC key generation, key-wrap stack schedules and some
fallible output allocations have additional cleanup opportunities. Those are
tracked hardening limits, not claimed remote exploits. Platform-specific native
execution beyond the retained Linux targets, external system-library overrides,
side-channel proofs and certification claims require separate evidence.
