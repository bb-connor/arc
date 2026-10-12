# chio-log-redact

`chio-log-redact` redacts operator log text through Chio's default pattern
redactor. It provides a `Display` wrapper for sensitive log expressions and a
tracing layer that sends redacted event targets and field values to a sink.
Sinks own formatting, escaping, storage, and delivery.

## Usage

Capture a redacted event without changing the process-wide subscriber:

```rust
use chio_log_redact::{MemoryRedactionSink, RedactionLayer};
use tracing_subscriber::prelude::*;

let sink = MemoryRedactionSink::default();
let subscriber = tracing_subscriber::registry()
    .with(RedactionLayer::new(sink.clone())?);
tracing::subscriber::with_default(subscriber, || {
    tracing::warn!(payload = "contact jane@example.com", "dispatch failed");
});
let events = sink.events();
assert_eq!(events.len(), 1);
assert!(events[0].fields.iter().any(|field|
    field.name == "payload" && field.value.contains("[REDACTED-EMAIL]")));
# Ok::<(), chio_log_redact::LogRedactError>(())
```

The example uses the crate's existing tracing dependencies and an in-memory
sink. At a log call site, `redacted!(value)` produces a `RedactedValue` using
the value's `Display` representation. `LogRedactor::redact_text` returns a
`Result<String, LogRedactError>` for explicit error handling.

## Guarantees

- `LogRedactor::new` and `with_classes` validate built-in pattern compilation;
  `RedactionLayer::new` and `with_classes` use this validated policy handle.
- `RedactedValue` and layer redaction replace redaction errors with
  `[REDACTION-FAILED]`. Their error fallback never exposes the original text.
  Free text functions return errors and do not perform startup validation.
- `RedactionLayer::on_event` redacts event targets and visited field values,
  including UTF-8-lossy rendering of byte fields. Field names pass through
  unchanged. Span fields are outside this layer's event-only output.
- Default classes enable secret patterns, basic PII, and bearer tokens.
  Coverage includes email, US phone and SSN patterns, Luhn-checked cards,
  selected API keys, JWTs, and long alphanumeric secret candidates.
  Pattern matching cannot establish that all sensitive content was removed.
- `redacted!` accepts one expression. Formatting-style invocations fail to
  compile; callers construct their structured log fields separately.

## Status

Implemented with tests for default and selected class policies, event fields,
byte values, and targets. `MemoryRedactionSink` is an unbounded test and probe
sink. The crate declares no Cargo features and is marked `publish = false`.
Selecting classes requires the dependency's `RedactClass` type; the default
backend accepts `pii_extended` and `custom` flags as no-ops.

A parallel tracing formatting layer can still observe the original event.
Route operator output through the redacted sink, and escape surviving control
characters when the sink writes one event per line.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol receipt redaction field](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Default redactor](../../guards/chio-data-guards/redactors/default/README.md)
- [SIEM export](../chio-siem/README.md)

License: [Apache-2.0](../../../LICENSE).
