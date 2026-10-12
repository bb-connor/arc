# chio-tee

Capture sidecar for Chio kernel observations. `ShadowRunner` redacts observed
requests, receipts, and inline invocation data, stores encrypted redacted
blobs, then emits tenant-signed `chio-tee-frame.v1` NDJSON for replay review.

## Usage

Apply the same mandatory redaction pass used before capture persistence:

```rust
use chio_tee::{RawPayloadBuffer, RedactClass, RedactPass};
let result = RedactPass::with_default().redact_or_fail_closed(
    RawPayloadBuffer::new(b"Contact alice@example.com".to_vec()),
    RedactClass::default_full(),
    false,
)?;
assert!(!result.manifest.matches.is_empty());
assert!(!String::from_utf8(result.bytes)?.contains("alice@example.com"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Embed `ShadowRunner::from_store` through `TrafficTap`, or feed `Observation`
NDJSON to the `chio-tee run` binary. Supply runtime directory, signing key,
tenant id, and an explicit at-rest key for a persistent blob store.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; capture/redaction and the binary are available. |
| `fips` | No | Routes the aliased core dependency through its FIPS feature. |

## Guarantees

- `RedactPass::redact_or_fail_closed` rejects redactor failures and, with
  paranoid mode, zero matches on payloads longer than 256 bytes.
- `ShadowRunner::capture` redacts all three payloads before persistence;
  frame blob hashes commit the redacted request and redacted full receipt bytes.
- `sign_frame` signs canonical frame fields excluding `tenant_sig`.
  `CaptureWriter::append` serializes appends and flushes each NDJSON line.
- `ShadowRunner::run` bounds each observation line to 16 MiB and stops on
  malformed input or capture failure, retaining earlier appended frames.

## Status

Implemented observation capture. Verdicts come from the supplied receipt;
the runner does not verify that receipt's signature or independently rerun
kernel policy. Hardware isolation and quote verification are outside this
crate. Enforce mode returns an error after recording a blocking verdict.
Mode upgrades require nonempty token text; callers own token authentication.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [chio-tee-frame](../chio-tee-frame/README.md)

[License](../../../LICENSE)
