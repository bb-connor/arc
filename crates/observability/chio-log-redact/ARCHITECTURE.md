# chio-log-redact architecture

## Responsibility and boundary

The crate places Chio's default pattern redactor between operator telemetry
values and a sink. Its public surface includes text functions, `LogRedactor`,
`RedactedValue`, `redacted!`, `RedactionLayer`, and `RedactedEventSink`.
It owns construction of redacted strings and event copies. Applications own
subscriber composition, sink formatting, resource limits, and persistence.

Redaction is pattern-based. It can remove matching API keys, token strings,
and basic PII while leaving unrecognized sensitive content unchanged.
It does not sign data or alter a receipt's signed `redaction_mode`.

## Structure

| File | Responsibility |
| --- | --- |
| `src/lib.rs` | Public re-exports, expression macro, policy and layer regression tests. |
| `src/engine.rs` | Text adapters, validated policy handles, error and display wrappers. |
| `src/layer.rs` | Event visitor, generic sink, closure adapter and memory sink. |

`LogRedactor` stores a copyable `RedactClass` selection. `RedactedValue`
stores the resulting string and implements `Display` and `as_str`.
`RedactedEvent` carries target, level, and `Vec<RedactedField>`.
The sink trait receives an owned event through `record` and returns no
acknowledgment or delivery error. Closures satisfying `Send + Sync + 'static`
implement the trait through a blanket implementation.

## Data and control flow

`LogRedactor::new` selects `RedactClass::default_full`; `with_classes`
validates every built-in pattern before retaining the requested classes.
`redact_text_with_classes` passes UTF-8 input bytes to the dependency's
`redact_payload` and checks that the replacement output is UTF-8.
It discards the dependency's match manifest and returns the redacted text.
The free text functions and `RedactedValue::new` do not run the startup
pattern validation themselves. Use a validated `LogRedactor` when setup
must reject an invalid pattern set.

`redacted!(value)` expands to immediate `RedactedValue::new(value)`.
The expression's `Display` text is materialized, redacted, and retained as a
string. The macro also accepts a trailing comma; formatting-style calls
produce a compilation error. `RedactedValue::with_redactor` reuses a
validated class selection, while `with_classes` selects flags directly.

`RedactionLayer::on_event` visits an original tracing event and creates a
separate event copy for its sink. Strings and scalar values become text;
debug fields use debug formatting and byte values use UTF-8-lossy conversion.
Every visited value and the metadata target pass through the policy.
Field names are copied unchanged and event level is preserved.
The layer has no span hook and does not rewrite the original tracing event.
Other subscriber layers can observe and export the original fields.

## Trust and invariants

Strict text and display methods return `LogRedactError` on redaction failure.
`RedactedValue`, the layer visitor, and placeholder display methods substitute
`[REDACTION-FAILED]` on error. The error path never uses the original value as
its fallback. This property is distinct from pattern coverage: unmatched
text remains in successful output.

The default selection enables `secrets`, `pii_basic`, and `bearer_tokens`.
The dependency matches selected AWS and API key formats, JWTs, long
alphanumeric candidates, bearer authorization strings, emails, US phones,
SSNs, and Luhn-checked card candidates. `pii_extended` and `custom` flags are
accepted but implement no extra matching in this default backend.
`RedactClass` is supplied by the dependency and is not re-exported here.
Selecting those flags does not load a replacement redactor module.

The crate performs no output control-character escaping, length limiting,
or sink sanitization. A line-oriented sink must encode surviving newlines
and other control characters. Applications must keep secrets out of field
names and attach operator output to the redacted sink. A callback can block,
panic, or persist data; the layer invokes it synchronously without an error
channel or retry mechanism.

`MemoryRedactionSink` stores an unbounded vector behind `Arc<Mutex<_>>`.
Its clones share events. `events` clones the current vector; both reads and
writes recover a poisoned lock's inner value. It is useful for tests and
embedding probes where the caller controls event volume.

## Dependencies

`chio-data-guards-redactors-default` provides `RedactClass`, pattern
compilation checks, and byte replacement. `tracing` provides events and field
visitation; `tracing-subscriber` supplies `Layer` and the registry lookup
bound. `thiserror` formats setup/redaction errors. The crate declares no
Cargo features, and the tracing registry support is an ordinary dependency
feature selected by its manifest.

## Verification

Tests in `src/lib.rs` exercise email and SSN masking, a secrets-only policy,
reused display policies, event field values, UTF-8 byte fields, targets, and
selected class propagation through the layer. The macro has a compile-fail
doctest for formatting-style invocation.

Run `cargo test -p chio-log-redact` for the crate suite. The repository's
`scripts/check-log-redaction.sh` scans selected kernel and SIEM source log
sites for unwrapped sensitive fields. Its text gate concerns those call
sites; it does not prove exhaustive pattern coverage or subscriber isolation.

See the [README](README.md),
[default redactor](../../guards/chio-data-guards/redactors/default/README.md),
and [receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract).
