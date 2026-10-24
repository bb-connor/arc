# chio-kernel-browser architecture

## Responsibility and boundary

This crate adapts portable Chio operations to a browser wasm-bindgen boundary
and exports Rust helpers for native tests and embedding. Its public surface
includes wire structs, `evaluate_pure`, capability and receipt verification,
content-bound signing, trusted-body relay signing, `BrowserClock`, and
`WebCryptoRng`. The wasm-only module exports JavaScript entry points.

The facade owns JSON conversion and platform clock/entropy adapters.
Applications supply trusted issuers, trust roots, and parent-budget snapshots.
Applications also own tool execution, revocation, persistent accounting, and
receipt-log storage. A local allow result describes portable admission only.

## Structure

`lib.rs` exports helpers and gates `wasm` on `target_arch = "wasm32"`.
`wire.rs` defines requests, verdicts, context snapshots, and `BindingError`.
`pure.rs` performs evaluation, signing, receipt checks, and authority/hex decoding.
`clock.rs` implements fallible browser time and a regression fence.
`rng.rs` supplies Web Crypto entropy and native stubs.
`wasm.rs` handles JSON strings, JavaScript values, and structured error conversion.

The crate declares `no_std` but explicitly links `std`; its browser clock uses
thread-local state. The kernel dependency disables defaults and remains the
portable computational dependency. The browser facade's dependencies have their
own target and runtime requirements.

## Data and control flow

`evaluate_pure` checks authorization extensions, decodes issuers, builds a trust
resolver, and seeds an in-memory registry from caller snapshots. It evaluates
with an allow-classical floor, negotiation context, optional direct root, and
empty guards. A supplied clock override uses `FixedClock`; otherwise evaluation
reads the injected clock. Core denial is serialized as a verdict.

Public signing requires canonical content bytes in the request and a decoded,
nonzero seed. It delegates content-hash and kernel-key checks to core signing.
The relay function explicitly accepts an upstream-trusted body without a
preimage. `verify_receipt_pure` decodes original signed JSON, recomputes receipt
identity, and returns individual signature, parameter, and trust results.
An empty issuer set permits inspection but never a trusted `ok` result.

## Trust and platform invariants

`BrowserClock` reads wall time from `Date.now()` and monotonic time from
`performance.now()`. It rejects nonfinite, negative, overflowing, or regressing
readings. The native adapter returns `ClockError::Unavailable`.
`WebCryptoRng::try_new` requires `globalThis.crypto.getRandomValues`; native
construction fails. Fills are chunked to the 65 536-byte Web Crypto quota. A
getRandomValues failure returns `RngError`, and `mint_signing_seed_hex`
reports it as `entropy_unavailable` without returning a seed.

A wasm host that provides no `globalThis.crypto` (for example WASI) cannot
mint seeds through this API.
The pure evaluation path inherits core denial of security bindings and
unsupported stateful enforcement. Caller snapshots are per-call inputs and
provide no durable cross-call counter updates. No registered guards run here.

## Dependencies

`chio-kernel-core` implements portable admission and signing. `chio-core-types`
supplies cryptographic artifacts, canonical decoding, and receipt identity.
Serde and serde_json handle the Rust wire structs. On wasm, wasm-bindgen,
js-sys, web-sys, and serde-wasm-bindgen implement JavaScript interoperability.
The manifest disables wasm-opt in the wasm-pack release profile.

## Verification

Native `src/tests.rs` covers portable verdicts, delegated budget snapshots,
unsupported extensions, receipt hash/preimage refusal, duplicate keys, trusted
signers, and malformed input. Clock unit tests exercise numeric boundaries.
Wasm integration files cover binding roundtrips, verdict matrix cases, and
receipt verification in a browser.

```bash
cargo test -p chio-kernel-browser
wasm-pack test --headless --chrome crates/kernel/chio-kernel-browser
```

The second command requires wasm tooling and Chrome. Native tests compile
without wasm bindings and establish only native helper behavior. Browser
qualification must execute the wasm tests in the required browser environment.
