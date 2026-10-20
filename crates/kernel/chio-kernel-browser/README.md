# chio-kernel-browser

Browser JavaScript bindings and Rust helpers over Chio's portable kernel.
The crate produces a `cdylib` for wasm-bindgen and an `rlib` for native tests.
Its underlying kernel dependency disables default features.

## Usage

Rust callers can check receipt envelopes through the same helper used by the
wasm facade. This host-runnable example rejects an incomplete envelope before
signature inspection; it requires no JavaScript runtime.

```rust
use chio_kernel_browser::verify_receipt_pure;

let result = verify_receipt_pure(b"{}", &[]);
assert!(result.is_err());
```

For JavaScript bindings, install `wasm32-unknown-unknown` and wasm-pack, then
build from the workspace root:

```bash
wasm-pack build crates/kernel/chio-kernel-browser --target web
```

The `wasm` module exports JSON-oriented evaluation, signing, capability
verification, receipt verification, and seed minting functions. Browser time
needs `Date.now()` and `performance.now()`; seed minting needs `globalThis.crypto`.
The HTML and JavaScript examples live in [examples](examples/demo.html).

## Guarantees

- `evaluate_pure` rejects unsupported authorization extensions and uses full
  portable verification with caller-supplied trust roots and budget snapshots.
- `sign_receipt_pure` requires the content preimage, rejects all-zero seeds,
  and calls core signing that refuses content-hash and kernel-key mismatches.
- `verify_receipt_pure` uses duplicate-aware signed JSON decoding, checks
  receipt identity, signature, parameters, and signer trust. Empty trusted
  issuers cannot produce a trusted `ok` result.
- `BrowserClock::read` rejects invalid or regressing readings.

## Status

Implemented browser facade with native helper tests and wasm browser tests.
Evaluation supplies an empty guard pipeline and an in-memory registry per call;
applications own durable accounting, revocation, tool execution, and receipts.
Native `BrowserClock` returns `ClockError::Unavailable`, and native
`WebCryptoRng::try_new` returns an unavailable error. Web Crypto is read from
`globalThis.crypto`, so browsers, Workers, Durable Objects, Deno and Node 20+
work; a host without it gets an unavailable error.
A failed RNG fill returns an error; seed minting then refuses.
Native tests do not exercise JavaScript bindings or browser APIs.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Portable kernel](../chio-kernel-core/README.md)
- [License](../../../LICENSE)
