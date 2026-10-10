# AWS-LC Rust wrapper provenance and owned DES repair

Reviewed October 7, 2026 by the executing Codex agent. Confidence is high for
source reconstruction and the reproduced DES validation repair, and moderate
for the selected FFI wrapper review. This is source review and executable
regression evidence, not an independent human cryptographic certification.

## Exact source

The published `aws-lc-rs` 1.18.1 archive has SHA-256
`b281d307588d634de920874890732659e2e7672f72b5e10e81badc1a8a83621e`.
It identifies upstream commit
`22e629d5c46276497a24ee3e575be4315940e7cb`. The archive contains 111 files.

The review downloaded that archive and the named upstream commit, checked
archive member types and extraction paths, applied the recorded
`third_party/aws-lc-rs-chio/CHIO-PATCH.patch`, and restored the 71 test fixtures
listed in `CHIO-RESTORED-FIXTURES.sha256`. Exactly eight fixtures require the
recorded whitespace transformation. All 183 reconstructed files match the
vendored tree byte for byte; the three Chio provenance files are review
metadata. There are no unexplained source differences.

The production change is confined to `src/cipher/key.rs`. The manifest makes
the fork unpublished and adds the regression target. Other changes normalize
five documentation punctuation occurrences and test-fixture whitespace.

## Examined boundaries

The wrapper depends on the separately audited `aws-lc-sys` 0.45.0 and optional
`aws-lc-fips-sys` 0.14.2 native implementations. This review does not replace
their existing archive/native-build audits.

Examined the normalized manifest and feature routing; `build.rs`; managed and
detachable pointer ownership in `src/ptr.rs`; system RNG and test-only RNG
exposure in `src/rand.rs`; FIPS service-indicator routing in `src/fips.rs`;
CBS/CBB/bignum ownership and output-buffer construction; EVP key parsing,
algorithm/length routing, borrowed native-key lifetimes and reference-count
ownership; and the entire symmetric-key preparation implementation changed
by the fork. Source inventory and ambient-authority scans cover all Rust
source files. This is not a claim that every cryptographic algorithm was
independently rederived.

The build script reads named build/test environment variables and dynamic
`DEP_AWS_LC_*` Cargo metadata, selects the native sys crate and forwards that
metadata. It opens no
network connection, launches no process and writes no filesystem artifact.
`dev-tests-only` exposes custom RNG implementations only in development/debug
profiles; the production workspace must not enable that feature in release
builds. The examined FFI wrappers retain allocations through RAII objects and check
null pointers and native status results at their call boundaries. CBB setup
also relies on the native constructor zero-initializing its state on failure.
The DES change accepts only the native success result.

## Reproduced defect and repair

DES key parity bits do not contribute to the effective key. The registry
release accepts native `DES_set_key` result `-1` (bad parity) and compares
TDEA key components with their parity bits intact. That permits a parity
variant of a known weak key, and parity-distinct encodings of an equal TDEA
component.

The fork normalizes to odd parity in a zeroizing temporary, accepts only
native result zero, and compares TDEA components after masking parity bits.
The comparison still uses the native constant-time equality facade. The
native key-schedule inputs and fixed sizes are preserved.

The existing three regression tests were run against the verified registry
source with only their manifest/harness and missing fixtures added. One
positive control passes, while the weak-key and equal-component tests fail
at parity mask one. The same target passes all three tests against the exact
vendored fork. Its library suite with `legacy-des` enabled passes 385 tests.

## Cargo-vet disposition

The accepted disposition treats this unpublished, modified path package as
owned source, consistently with the other genuinely reviewed local forks.
The original registry release receives no new `safe-to-deploy` certificate
and no exemption. Its known optional DES defect prevents describing the
registry bytes as the repaired package. All registry/native dependencies
remain subject to the existing deployment criteria.

A separate peer reviewer independently reconstructed all 183 payload files,
checked the native DES/constant-time contracts and reviewed the retained
positive and negative test results. The reviewer found no P0-P2 blocker in
the exact owned-fork delta or provenance. Cargo-vet's ownership declaration
is not itself an independent audit.

## Executed checks and limits

```sh
CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 cargo +1.94.1 test --locked \
  --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --features legacy-des --lib --test des_parity_regression
```

The fresh run used a separate target directory on native macOS arm64. The
385 library tests and three DES regressions passed. The original-source
negative run used another target directory and returned the expected two
failures. No fresh Linux, Windows or FIPS execution is inferred from these
checks. Historical Linux/FIPS results beside the fork are retained but are
not presented as current-platform qualification.

Current raw evidence is under
`target/recovery-pr/dependency-security/aws-lc-review/` and
`target/recovery-pr/dependency-security/aws-lc-tests.log`. The verified
registry source is available at
<https://static.crates.io/crates/aws-lc-rs/aws-lc-rs-1.18.1.crate>.
