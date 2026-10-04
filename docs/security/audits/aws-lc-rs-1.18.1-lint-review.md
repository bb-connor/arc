# Standalone AWS-LC lint boundary

Date: 2026-10-04. Scope: the Chio `aws-lc-rs 1.18.1` fork, including build.rs,
default production library, optional legacy DES, and a separate FIPS library
selection. The source inventory and complete reconstructed patch identify the
reviewed bytes. This supplements the upstream/fork audit; it does not certify
the flawed registry archive or establish panic freedom.

## Defect and bounded repairs

Root workspace Clippy does not lint the excluded path crate. Direct standalone
Clippy reproduced an unguarded build.rs unwrap, then 45 default-library sites.
Backend measurement exposed nine additional legacy sites and three FIPS sites.
The library and build script now have unconditional unwrap/expect deny attributes,
which preserve the source's Rust 1.71 attribute syntax compatibility.

Existing fallible boundaries now propagate errors: build PROFILE lookup, two
private cipher-descriptor helpers, streaming key/IV length conversions, six DES
slice conversions, private-key serialization, and hexadecimal decoding. The
Ed25519 validator compares the native signed bit count directly with its bounds.
Streaming constructors validate native IV length before FFI in release builds as
well as debug builds. Existing key checks and error types remain intact.

The FIPS RSA validation predicate now returns false for a non-RSA key. Its new
test first failed on the original expect and then passed after the repair.

## Preserved upstream contracts

The [exact disposition inventory](../../../supply-chain/aws-lc-lint-exceptions.json)
names every allowed item, rationale, lint, feature selection and compiler byte
span, with source file hashes. Source comments identify the same stable IDs.
There are 34 narrow items covering 39 distinct sites, not a crate-wide allow.

- `From` and `Clone` retain their upstream infallible interfaces, including
  existing native derivation, initialization, allocation and copy failure panics.
  No default key or ignored native error is substituted.
- Digest, HMAC, PBKDF2, Ed25519 and FIPS assertion wrappers retain their explicit
  compatibility panic contracts. Existing fallible alternatives remain available
  where upstream supplies them. Input limits are not weakened or truncated.
- Fixed key halves, nibble conversion, attached pointer ownership, nonnull
  zeroization references, bundled native nonnegative size results and RSA key
  predicate equivalence provide the recorded invariant-based dispositions.
- `test::TestCase::consume_usize` is a public panic-oriented test helper compiled
  in the library. Its exception is measured; it is not hidden as cfg(test) code.

The policy does not address every possible assertion, index, allocation, explicit
panic or panic in a nested call. Additional fallible public API design is a
separate upstream-compatibility decision, not part of this prerequisite.

## Enforcement and evidence

`scripts/check-supply-chain.sh` invokes the standalone deny pass and a second
Clippy JSON pass with force-warn. Force-warn exposes even locally allowed sites;
the checker independently rejects any difference from the reviewed inventory.
Source hashes detect scope changes even when the currently measured site count
would remain the same. Both required audit workflows install Clippy explicitly.

The default/legacy selection measures 37 sites and FIPS measures 38. cfg(test)
fixtures, examples and benchmarks are not Clippy targets. This Linux coverage
does not claim every platform configuration is executed. Native dependencies
and deployment feature restrictions retain their separate source-audit gates.

Retained real-compiler controls verify accepted sites, an unallowed new unwrap,
an added unwrap inside an existing allow, a legacy-only added site, removed deny
floors, broadened allows, missing measurements and duplicate dispositions.
Workflow controls reject removal of the mandatory checker or its negative tests.
Local aarch64 Rust 1.95.0 library results: 386 default/legacy and 492 FIPS tests
passed. The initial wrong-key FIPS failure remains distinct from the repaired
campaign. Hosted candidate checks and final independent audit acceptance are
recorded in the landing ledger and PR review, not inferred from these local runs.
