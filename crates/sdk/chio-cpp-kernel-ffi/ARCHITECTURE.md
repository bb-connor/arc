# chio-cpp-kernel-ffi architecture

## Responsibility and boundary

Nine C symbols expose ABI/build information, buffer release, evaluation,
capability verification with basic or full context, portable-passport verification,
and two receipt signing paths. `ChioKernelFfiBuffer` and `ChioKernelFfiResult`
carry Rust-owned bytes and numeric status/error fields with C layout.
`sdks/cpp/chio-cpp-kernel` consumes the generated header and static library.

This boundary accepts caller-selected authority keys, time, delegation roots,
and parent budgets. The integrator must authenticate that context and decide
how offline verdicts control execution. Evaluation and signing are independent
exports: a caller with a seed can submit a body without first calling evaluate.
The ABI has no evaluation handle connecting those operations.

## Structure

`src/lib.rs` owns exported functions, Serde request/response envelopes, input
conversion, snapshot validation, kernel invocation, and error mapping.
`src/tests.rs` exercises internal string helpers and exported symbols.
`cbindgen.toml` selects the surface emitted in `include/chio/chio_kernel_ffi.h`.
There is no Cargo build script producing headers.

`EvaluateRequestEnvelope` includes capability, trusted issuers, request, optional
clock and peer profile, optional direct-root capability, per-issuer scope roots,
and parent-budget snapshots. `VerifyCapabilityRequestEnvelope` uses the same
context with a `token` field. Verification returns an owned metadata snapshot
including serialized scope and evaluated time.

## Evaluation and capability flow

`evaluate_json_str` parses the envelope with Serde. Governed intent, approval
token(s), threshold proposal, and supplemental authorization fields reject when
present or nonempty because this bridge cannot authenticate those extensions.
The capability and optional direct-root value then decode to typed tokens.

Trusted issuer strings decode as public keys. Trust-root map keys also decode
as public keys; their scope-hash strings must be nonempty, unpadded, and free of
control characters. Snapshot parent and child IDs must be nonempty and unpadded.
`seed_budget_registry` registers each parent share and admits its recorded
children through `InMemoryBudgetRegistry`, rejecting invalid shares or conflicts.

A supplied evaluation `now_secs` selects `FixedClock`, including zero; omission
selects `SystemClock`. Verification accepts signed time values: nonnegative
values use `FixedClock`, while negative values or an omitted context timestamp
use the system clock. The basic capability entrypoint supplies one trusted
issuer, the default peer profile, no direct root, no trust roots, and no snapshots.
Delegation requiring those inputs needs the context entrypoint.

`evaluate_with_full_floor` receives `AllowClassical`, the peer profile
(default `t1_default`), root resolver, and seeded registry. Kernel-core checks
capability validity and bindings, then subject, portable scope, and sibling
admission. The bridge passes zero guards and no session filesystem roots.
The response carries `verdict`, optional reason, and matched grant index;
`PendingApproval` becomes `deny`. A deny response still has ABI status OK because
evaluation completed successfully. Invalid envelopes/context return error status.

Capability verification calls `verify_capability_full` and serializes
its verified snapshot. Passport verification calls `passport_verify::verify_passport`
with the original envelope bytes, trusted issuer, and selected clock. It returns
subject/issuer/time metadata and the canonical payload bytes encoded as hex.

## Signing and trust invariants

The public three-argument signer decodes a receipt body, hex content preimage,
and Ed25519 seed. `core_sign_receipt` hashes the supplied bytes, rejects a content
hash mismatch before key/signing work, and checks the body's kernel key against
the backend key. Mismatch maps to SIGNING_FAILED or KEY_MISMATCH respectively.
The FFI decodes bytes; it does not prove they came from an evaluation or validate
that they are the canonical representation of some separately delivered content.
The caller must bind the supplied preimage to its actual output.

The relay signer invokes `sign_receipt_relaying_trusted_body` and checks the
kernel key while trusting the supplied content hash. Its caller must establish
upstream body trust and use the relay only to forward that body when its
content preimage is unavailable. The protocol forbids relay signing on paths
holding evaluated content; those callers must use
`chio_kernel_sign_receipt_json` with its preimage so the recompute check runs.
The relay does not enforce this restriction.
Neither signing export persists the receipt or advances a
Merkle log. Both use an Ed25519 backend created from caller seed input.

JSON evaluation, capability, and receipt-body inputs use ordinary Serde parsing;
these entrypoints do not add duplicate-aware raw signed-wire admission.
Passport input passes directly to the core verifier's strict signed-wire decoder,
which rejects duplicates and bounds envelope input at 16 MiB. Payload bytes remain
opaque: native passport credentials and issuer-chain checks require their own
validators.
Every request creates a new budget registry, so snapshot admission does not
persist across calls. Persistent revocation, invocation/spend enforcement, DPoP
replay, transport dispatch, and receipt storage belong to the runtime integrator.
Aggregate invocation and cumulative approval enforcement are rejected by the
portable evaluation path when required by a token. Capabilities carrying an
authenticated security binding also reject because the portable evaluator lacks
the authoritative security context.

## Pointer ownership, errors, and threading

`read_c_str` rejects null and invalid UTF-8, then copies valid input to an owned
`String`. The caller must keep readable NUL-terminated memory stable during that
copy; arbitrary addresses cannot be validated by null checks. Interior NUL bytes
truncate string input. All exports are synchronous with no retained foreign
pointers, callbacks, or session handles. The exports have safe Rust `extern "C"`
signatures; raw-pointer dereferences still impose the caller obligations above.

Output is a boxed byte slice transferred with `Box::into_raw`; release reconstructs
it with `Box::from_raw`. Preserve the pointer and length, read only within the
range, and call `chio_kernel_buffer_free` exactly once for nonempty results,
including error messages. There is no added NUL terminator. Cross-thread access
requires caller synchronization, including the sole release owner.

Status codes are OK 0, ERROR 1, PANIC 2, and NULL_ARGUMENT 3. Error codes distinguish
JSON, hex, capability, passport, key mismatch, signing, and internal failures.
Invalid UTF-8 maps to INVALID_JSON. `run_ffi` catches unwinding panics in the
processing closure; reads and frees are outside it. Undefined behavior and
aborting panics cannot be converted into these results. ABI 2 requires the
three-argument signer declaration; clients must check the version before use.

## Dependencies and verification

`chio-core-types` provides capability/receipt types, keys, and Ed25519 backend.
`chio-kernel-core` provides verification, clocks, scope evaluation, signing, and
budget registry semantics. `hex` handles preimages and payload encoding;
`serde`/`serde_json` handle envelopes and response serialization.

Run `cargo test -p chio-cpp-kernel-ffi`. Tests cover matching/out-of-scope evaluation,
unsupported authorization, delegated sibling budgets, trust-root errors, epoch
zero and clock overflow, expiry, invalid JSON/null pointers, buffer release,
content hash accept/refuse, trusted relay signing, and ABI 2.
`crates/kernel/chio-kernel-mobile/tests/cross_ffi_parity.rs` compares shared
verdict cases. `sdks/cpp/chio-cpp-kernel/scripts/check-with-ffi.sh` builds and tests
the Rust library plus the C++ wrapper using its declared toolchain prerequisites.
