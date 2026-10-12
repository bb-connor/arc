# chio-provider-conformance architecture

## Responsibility and boundary

The library owns fixture loading, native adapter replay, and deterministic
comparison of projected invocations, captured verdicts, and lowered outputs.
ProviderCaptureFixture retains scenario identity and ordered capture records.
ReplayOutcome reports mode and counts for the completed comparison.

CapturedVerdict values are expectations supplied by a fixture. Their presence
is not a live kernel authorization or receipt signature verification.
The record binary owns credential-driven refresh of supported existing scenarios.
Library assertions work without provider features or network access.

## Structure

capture.rs defines CaptureRecord, direction enums, schema, and fixture paths.
input.rs defines the bounded regular-file reader and shared JSON ingress exports.
assertions.rs compares canonical JSON bytes and exact VerdictResult values.
loaded_weights.rs re-exports core byte-digest and unavailable-weight contracts.
replay.rs coordinates provider modules and local manifest admission fixtures.

replay/fixture.rs validates capture files and exposes fixture enumeration.
replay/payload.rs extracts provider-specific envelope and identity fields.
replay/stream.rs reconstructs SSE or NDJSON inputs from ordered records.
replay/assert.rs compares projected calls, verdicts, and native lowerings.
replay/openai.rs, anthropic.rs, bedrock.rs, and additional_providers.rs
contain the provider replay paths selected by Cargo features.

src/bin/record.rs wires CLI, credentials, invocation, and process helpers.
The recorder's provider enum supports OpenAI, Anthropic, and Bedrock.
Its fixture writer replaces recordings atomically after assembling records.

## Data and control flow

Fixture discovery returns provider scenario paths under the package fixtures root.
load_fixture reads bounded UTF-8 NDJSON, decodes original JSON records, and
checks schema, provider consistency, scenario identity, and record count.
Provider stream replay separately checks supported lifecycle sequences.
Replay extracts captured evaluator expectations and provider principal labels.

Feature-enabled replay constructs the corresponding adapter and local admitted
manifest security where required. It projects captured batch or stream traffic,
compares normalized invocation fields, compares evaluator outcomes, and checks
lowered provider results using canonical byte equality.
Some normalization removes runtime timestamps so replay comparisons remain stable.
The resulting counts describe fixture processing rather than external dispatch.

The recorder loads an existing scenario seed, obtains provider credentials,
invokes its provider request path, assembles refreshed records, and writes them.
Recording can contact external services and replace fixture files.
Offline assertion and replay use cases do not require the recorder.

## Trust and invariants

read_fixture requires a regular file and limits its read to the document bound
plus one byte so oversized inputs are detected without unbounded allocation.
On Unix the open flags include NOFOLLOW and NONBLOCK. Other platforms check
symlink metadata before opening; this does not claim identical race semantics.
The shared original JSON reader rejects duplicate keys before typed projection.

assert_canonical_json_eq serializes both inputs with canonical encoding and
returns AssertionError on mismatch. assert_verdict_eq compares typed values.
A captured Allow is replay data, not a newly admitted tool invocation.
Provider features control adapter availability; disabled replay reports an error.
No crate API certifies external-provider availability or operational policy.

## Dependencies

Optional provider adapters implement the native projections under test.
chio-manifest supplies local registry admission for feature-enabled replay.
chio-provider-adapter-core supplies shared ingress; chio-core-types supplies
canonical encoding and loaded-weight contracts. serde defines capture projection.
rustix supports safe Unix fixture opens; tempfile and tokio support recording.
clap parses recorder arguments, while chrono timestamps captured activity.

## Verification

Run cargo test -p chio-provider-conformance for shared fixture and assertion tests.
Enable a fixtures-* feature to run its corresponding replay integration target.
Run all features together to include tests/cross_provider_equality.rs.
tests/producer_numbers.rs checks ordinary decimal inputs through native adapters.
tests/replay_openai.rs checks missing-verdict rejection as well as corpus replay.
input.rs tests oversized files, symlinks, directories, and Unix FIFOs.

These tests measure local corpus behavior and canonical consistency.
Actual recording requires provider credentials and separate operational evidence.

## Navigation

- [Usage and features](README.md)
- [Shared provider ingress](../chio-provider-adapter-core/ARCHITECTURE.md)
- [Capture corpus](fixtures/)
