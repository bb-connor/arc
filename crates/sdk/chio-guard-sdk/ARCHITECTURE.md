# chio-guard-sdk architecture

## Responsibility and boundary

The SDK owns the guest side of the Rust guard ABI. `GuardRequest` contains
tool, server, agent, arguments, scopes, and optional host-extracted action
context. `GuardVerdict` represents allow or deny with a reason.
These values describe a guard evaluation; capability validation and signed
receipt production belong to the host kernel.

The crate re-exports request decoding, verdict encoding, host wrappers,
and types at its root. `prelude` exposes the guard authoring subset.
Raw allocator and deny-reason exports remain in their modules.

## Structure

| Module | Role |
|--------|------|
| `types` | Serde request shape, verdict constants, reason normalization, and `GuestDenyResponse`. |
| `glue` | Unsafe request read, verdict encoding, thread-local deny reason, and `chio_deny_reason`. |
| `alloc` | `chio_alloc` and `chio_free`, backed by thread-local `Vec<u8>` allocations. |
| `host` | Logging, configuration, time, blob imports, and `PolicyContext`. |

`serde` derives the request and deny-response JSON representations.
`serde_json` performs their encoding and decoding. There are no internal
Chio dependencies or declared Cargo features.

## Data and control flow

The host requests memory through `chio_alloc`, writes request JSON there,
and calls the guest's evaluation export. `read_request` converts that
region into an owned `GuardRequest`. Guard logic returns a verdict, which
`encode_verdict` maps to zero for allow or one for deny.

Encoding allow attempts to clear the thread-local reason. Encoding deny
normalizes and attempts to store it. The host subsequently calls
`chio_deny_reason` with a writable buffer to retrieve `{"reason": ...}`.
The reason persists until it is replaced or cleared; retrieval does not
consume it. Storage uses `RefCell::try_borrow_mut`, so updates can be skipped
when the cell is already borrowed.

On WASM, `log`, `get_config`, and `get_time` use imports from `chio`.
`fetch_blob` calls `chio:guard/host@0.2.0` with a host-owned handle and byte
range. `PolicyContext::read` delegates to it. `PolicyContext::close` has
an empty body; resource reclamation remains a host responsibility.

## Trust and invariants

`read_request` rejects `ptr <= 0` and `len < 0`; zero length produces a JSON
decode error. Positive bounds are used to form a raw slice without checking
the linear-memory extent. The caller must ensure the full region is live
and readable. Request decoding uses ordinary Serde JSON; it neither
validates capabilities nor verifies signed payloads.

`chio_deny_reason` checks signed bounds and output capacity before creating
a mutable slice. The host must supply a valid writable region. These ABI
pointers are `i32`; native 64-bit heap addresses can truncate and must not
be used to exercise the successful memory path.

`chio_alloc` returns zero for nonpositive sizes and stores zeroed vectors
for positive sizes. It uses an infallible vector allocation; allocation
failure has no recoverable error branch. Tracking also uses a fallible
`RefCell` borrow. `chio_free` rejects nonpositive values and removes a vector
only when its pointer and length match the supplied pair.

Configuration uses a 4096-byte output buffer. Blob reads allocate the
requested length. Both wrappers clamp a positive reported length to the
buffer size, but the host must honor the buffer during the imported call.
Host errors yield `None` for config and `Err` for blob reads.

## Verification

Run `cargo test -p chio-guard-sdk` for inline tests. `types` checks optional
field defaults, omitted fields, request round trips, and reason normalization.
`glue` checks reason lifecycle and invalid pointer/length rejection; successful
decode and reason serialization tests use pure JSON logic to avoid truncated
native pointers. `alloc` checks size rejection and allocation tracking paths.

`host` tests cover native fallbacks and handle wrapping. Those fallbacks
perform no WASM import calls. `cargo test -p chio-wasm-guards` exercises
the host-side runtime; its Rust guest fixtures require the WASM target.
See the [README](README.md) for an offline request/verdict example.
