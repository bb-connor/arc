# chio-adversarial-suite architecture

## Responsibility and boundary

The public surface defines `AdversarialCase`, `AttackClass`, `ExpectedVerdict`,
`CoverageCase`, and `CaseError`, plus bundled loaders and manifest types.
A case owns its expected reason, threat identifier, pending flag, notes, and
class-specific JSON artifact. The consumer owns attack execution and comparison
of actual security decisions with those expectations.

The loader validates the common envelope. It does not verify signatures,
execute tools, enforce capability policy, or interpret each artifact's shape.
`CoverageCase` wraps a validated non-pending envelope. This eligibility marker
still requires evidence from a downstream harness before coverage is asserted.

## Structure

- `src/lib.rs` contains the envelope, attack-class vocabulary, validation,
  coverage wrapper, loading functions, and unit tests.
- `src/bundled.rs` defines `BundledCase` and the `BUNDLED_CASES` static list;
  `include_str!` embeds each listed vector at compile time.
- `src/manifest.rs` defines `Manifest`, `ManifestEntry`, and stable producer
  and schema constants, and renders the cross-SDK answer key.
- `cases/` holds vectors grouped by class. `schema/case.schema.json` is also
  exposed through `CASE_SCHEMA_JSON`; the Rust loader does not run a JSON
  Schema validator.

## Data and control flow

`from_path` reads bytes and delegates to `from_slice`. The byte loader uses
Serde JSON deserialization and then semantic validation. Errors propagate as
`CaseError`, retaining I/O, JSON, and semantic failure categories.

`bundled_cases` applies that loader to the embedded list in declaration order.
`bundled_cases_by_class` loads the whole list before filtering. A malformed
case in another class therefore also prevents that call from succeeding.
`bundled_coverage_cases` converts every case through `into_coverage_case` and
fails when any pending case is encountered.

`Manifest::from_bundled` loads the corpus, checks each path suffix against its
case id, skips pending entries, and hashes each included file's original bytes.
It sorts entries by id and records their count. Consumers can use those hashes
to detect changes to case files, including whitespace changes.

## Trust and invariants

Serde rejects unknown envelope fields and verdicts outside the single `DENY`
variant. `validate` requires schema version 1, restricted identifier/reason/
threat-id syntax, nonblank supplied notes, and a nonempty object artifact.
Direct construction is public; callers should validate before using an envelope.
`into_coverage_case` repeats validation before granting the coverage wrapper.

The manifest is unsigned metadata. `to_canonical_json` uses Serde's pretty
serialization in struct field order and appends a newline. Despite the API
name, this is not an RFC 8785 signing canonicalizer. Its guarantee is stable
output for the same manifest value under the serializer used here.
The checked-in manifest's byte equality is enforced by integration tests.
Deserializing a `Manifest` alone does not recheck counts or content hashes.

## Dependencies

`serde` and `serde_json` implement envelopes and opaque artifact values.
`sha2` hashes original case bytes, and `hex` encodes manifest hashes.
`thiserror` defines load and validation errors. The crate has no Chio runtime
dependency and declares no Cargo features.

## Verification

Run `cargo test -p chio-adversarial-suite` from the workspace root.
Unit tests cover malformed envelopes, schema and verdict rejection, pending
coverage refusal, bundled loading, and manifest ordering and formatting.
`tests/manifest_emit.rs` checks included classes and ids, bundled paths, and
byte equality between the emitter and checked-in `manifest.json`.

The ignored `regenerate` test rewrites that file only when explicitly invoked:
`cargo test -p chio-adversarial-suite --test manifest_emit -- --ignored regenerate`.
These checks establish corpus consistency. Concrete denial behavior is tested
by the consuming trust-boundary crates.
