# chio-kernel-mobile architecture

## Responsibility and boundary

The crate owns JSON-oriented synchronous Rust APIs and generated UniFFI
scaffolding for app embedding. `evaluate`, signing functions, capability
verification, passport verification, attestation challenge/verification functions,
and receipt-envelope inspection are public. Metadata records and
`ChioMobileError` cross the language boundary through the UDL definitions.

Calls execute in the app process. The host app owns tool invocation, receipt
storage/upload, revocation, authoritative budget state, platform evidence
collection, issuer pins, and challenge/counter lifecycle. Rust-side FFI parity
alone cannot establish device or operating-system enforcement.

## Structure

`lib.rs` contains request conversion, context decoding, budget seeding, and API
entry points. `errors.rs` defines UniFFI-compatible error variants.
`clock.rs` delegates to the shared `SystemClock`. `rng.rs` wraps getrandom.
`src/chio_kernel_mobile.udl` defines the language surface; `build.rs` generates
scaffolding that `include_scaffolding!` incorporates. `examples/bindgen.rs`
provides the workspace-locked bindings generator. The bindings directory holds
Swift and Kotlin integration instructions.

## Data and control flow

`evaluate` parses JSON and rejects unsupported authorization extensions before
building the portable request. Positive `now_secs` values select a checked fixed
clock when representable; other inputs use `MobileClock`. It decodes trusted
issuers, creates a scope-hash resolver, seeds a fresh registry, and calls
`evaluate_with_full_floor_and_root` with an allow-classical floor and no guards.
The adapter also denies matched grants requiring mediated authorization.
Ordinary denial becomes a JSON response; malformed inputs become FFI errors.

`sign_receipt` parses a body, decodes a nonzero 32-byte seed and content hex,
and calls core content-bound signing. The relay function omits the preimage
check and requires upstream body trust. Capability verification returns a
snapshot; passport verification returns metadata and encoded payload bytes.

## Trust and platform invariants

Portable admission inherits core refusal of authenticated security context,
aggregate invocation enforcement, and cumulative approval enforcement.
Per-call parent snapshots can constrain delegated share admission but do not
persist usage across calls. The host must preserve trusted time and admission
context; exposed clock overrides support deterministic testing.

`attest_app_attest` and `attest_play_integrity` emit challenge envelopes with
`requires_platform_evidence` status. They do not call the device APIs.
App Attest evidence verification requests production verification and disables
development fixtures. Play Integrity verification disables caller-supplied JWKS.
Production Play Integrity verification is currently unavailable: the pinned
Google key is a synthetic fixture, so the custody verifier rejects it through
its production-readiness guard. Custody test or `dev-fixtures` builds have a
separate fixture path; that path establishes only fixture behavior.
`inspect_mobile_receipt_envelopes` performs non-authoritative shape inspection.
The app must acquire evidence and manage replay/counter state separately.

`MobileRng` returns `RngError` when the OS entropy call fails and never
zero-fills. Signing with caller seeds independently rejects all-zero
seeds. `MobileClock` retains the shared clock's fallible reading contract.

## Dependencies

`chio-kernel-core` supplies admission and signing; `chio-core-types` supplies
artifacts and crypto. `chio-custody-hw` supplies platform evidence verifiers.
Serde, serde_json, hex, and sha2 handle wire conversion and challenge hashes.
UniFFI generates scaffolding and bindings; getrandom supplies native entropy.
The crate uses hosted shared types and emits staticlib, cdylib, and rlib artifacts.

## Verification

`ffi_roundtrip` tests verdict conversion, malformed input, delegated budgets,
content/key/seed signing refusal, passport checks, and attestation envelopes.
`cross_ffi_parity` compares the Rust-facing mobile API with the C ABI adapter.
`oracle_round_trip` signs mobile receipt fixtures and checks export records with
a local fixture oracle; it does not contact a hosted service.

```bash
cargo test -p chio-kernel-mobile
./scripts/qualify-mobile-kernel.sh
```

The script requires host FFI tests and at least one passing target-backed lane.
Apple lanes need Darwin, Apple SDKs, and `aarch64-apple-ios` or
`aarch64-apple-ios-sim`. Android arm64 needs `aarch64-linux-android`, cargo-ndk,
and an Android NDK. Missing environments receive explicit lane status.
