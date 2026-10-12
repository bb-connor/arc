# Default redactor architecture

## Responsibility and boundary

`redact_payload` transforms a byte slice into `RedactedPayload`, containing
output bytes and a `RedactionManifest`. `redact` selects the supported default
classes and returns bytes alone. `RedactClass` selects pattern groups.
`PASS_ID` identifies the pass implementation in each manifest.

The crate owns pattern matching and replacement. Callers own buffering,
persistence, tenant override selection, signing, and handling failed passes.
A returned manifest contains match metadata and elapsed time; constructing it
does not sign or authenticate the output. The public structs mirror the
redaction WIT contract without implementing a component loader.

## Structure

The implementation lives in `src/lib.rs`. Shared `PATTERN_*` constants define
the pattern inventory. `LazyLock<Option<Regex>>` instances compile each pattern
once. `DEFAULT_PATTERNS` uses those constants for startup validation.

`collect` delegates to `collect_with_filter`, which accepts nonoverlapping
matches and records replacement spans. `apply_spans` builds output bytes in
original-offset order. `luhn_ok` validates credit-card candidates after removing
spaces and hyphens. Unit tests live alongside the implementation;
`tests/integration.rs` exercises JSON-shaped receipts and HTTP-like logs.

## Data and control flow

The pass scans enabled secret patterns first, Bearer patterns second, and
basic PII patterns last. A candidate overlapping an accepted span is skipped.
This makes earlier pattern selection affect the class and replacement recorded
for overlapping text. Matches always refer to the original input coordinates.

Each accepted span receives a class-specific replacement. API key patterns use
`[REDACTED-API-KEY]`; long alphanumeric runs use `[REDACTED-BEARER]`. Bearer
matching accepts a Bearer-shaped substring and does not require an HTTP
Authorization header. Basic PII replacement markers identify email, phone,
SSN, or card candidates. The completed manifest sorts matches by offset and
length and stamps the elapsed microseconds and pass identifier.

`default_full` enables secrets, basic PII, and Bearer tokens. `all` additionally
sets `pii_extended`, which has no implementation here. Both `pii_extended` and
`custom` are accepted without extra matching. The derived default flag set
leaves the payload unchanged.

## Trust and invariants

The byte regex engine accepts non-UTF-8 input. ASCII patterns and replacement
spans preserve unrelated UTF-8 bytes in tested Unicode payloads. No JSON parse
or canonical serialization occurs during redaction. Pattern matching detects
syntactic candidates, including the long-run heuristic; it does not measure
entropy or prove that all sensitive data has been removed.

`collect_with_filter` converts match offsets and lengths to `u32` and returns
`RedactError::Overflow` when conversion fails. This checks recorded locations;
it is not a blanket input-length rejection. `InvalidUtf8` is available to
callers but is not emitted by the byte-oriented primary pass.

`try_compile` logs and returns `None` on constant compilation failures. The
runtime consequently skips that pattern. Strict startup behavior requires
calling `validate_default_redactor_compiles` and rejecting its error. Callers
must refuse persistence on redaction errors and decide how to handle startup
validation failures. Neither refusal is enforced inside this library.

## Dependencies

`regex::bytes` supplies compiled byte matching. Serde supports serialization of
class flags, matches, manifests, and payload structs. `thiserror` defines the
public error display. Standard-library timing and lazy initialization support
pass metadata and pattern reuse. No network or database dependency is required.

## Verification

Unit tests cover common secret formats, card filtering, overlap handling,
Unicode adjacency, and pattern inventory consistency. Integration fixtures
check receipt-like payloads, HTTP-like logs, disabled-class behavior, original
match offsets, replacement markers, and pass identifiers.

Run `cargo test -p chio-data-guards-redactors-default`. Those fixtures verify
local byte transformations. Caller persistence refusal, component loading,
and signing require verification in the consuming host.
