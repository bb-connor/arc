# chio-kernel-core

Portable capability evaluation and receipt signing for Chio kernel adapters.
The library is `no_std + alloc`; default features enable hosted dependencies
and the revocation snapshot surface. It supplies computation used by browser,
mobile, and native kernels.

## Usage

Verify an incoming portable passport before consuming its payload. This small
example exercises malformed-envelope rejection with a deterministic clock.
It runs on the host with the crate's existing dependencies.

```rust
use chio_kernel_core::{verify_passport, FixedClock, VerifyError};

let clock = FixedClock::new(1_700_000_000);
let result = verify_passport(b"{}", &[], &clock);
assert!(matches!(result, Err(VerifyError::InvalidEnvelope(_))));
```

For tool calls, supply `EvaluateInput` to `evaluate` and inspect its returned
`EvaluationVerdict`. Configure a crypto floor, trust-root resolver, and budget
registry through the corresponding `evaluate_with_full_floor*` APIs when needed.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables `std` and `revocation-view`. |
| `std` | Yes, via `default` | Enables hosted support in shared types and Serde. |
| `revocation-view` | Yes, via `default` | Adds the `arc-swap` snapshot cache; implies `std`. |
| `kani` | No | Enables the shared types' Kani hash backend. |
| `fuzz` | No | Exposes receipt replay fuzz helpers; implies `std`. |
| `dudect` | No | Enables the two timing harnesses; implies `std`. |

## Guarantees

- `evaluate` checks issuer/signature/time, subject binding, scope, and ordered
  synchronous guards. Guard errors and denial produce a deny verdict.
- `sign_receipt` checks the supplied content bytes against `content_hash` and
  checks the signing key. `sign_receipt_with_handle` consumes a signing handle.
- `sign_receipt_relaying_trusted_body` trusts the upstream content hash; callers
  own the integrity of that upstream body.
- `verify_passport` checks envelope/schema, pinned issuer, canonical signature,
  subject presence, and the validity window.

## Status

Implemented pure kernels and bounded formal helper surfaces. Tool transport,
receipt persistence, authoritative revocation lookup, invocation accounting,
and DPoP replay state belong to the host. Portable evaluation denies security
bindings requiring authenticated host context. Full portable evaluation also
denies aggregate invocation and cumulative approval enforcement requirements.
The portability script covers host and `wasm32-unknown-unknown` builds with
`--no-default-features`; other target acceptance needs separate evidence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Capability contract](../../../spec/PROTOCOL.md#5-capability-contract)
- [Native kernel](../chio-kernel/README.md)
- [License](../../../LICENSE)
