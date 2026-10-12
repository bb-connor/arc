# chio-spec-validate architecture

## Responsibility and boundary

The public surface consists of `load_json`, `validate`, `validate_value`,
and `ValidateError`. The library checks JSON document shape against a
caller-supplied schema. xtask uses this check for conformance scenarios and
fixture gates; the standalone binary exposes the file-based entrypoint.

Schemas are trusted inputs. Instance validation does not establish signer
identity, receipt integrity, capability freshness, or authorization.
Those properties require the corresponding runtime validators. Ordinary JSON
parsing here also does not enforce the canonical signed-artifact input rules.

## Structure

All library logic lives in `src/lib.rs`: JSON loading, option construction,
reference retrieval, Chio schema identifier lookup, and error reporting.
`src/main.rs` handles the two positional CLI arguments and exit status.
There is no persistent compiled-schema cache or daemon state.

`ValidateError` separates I/O, JSON parsing, schema compilation, and schema
violation failures. A violation retains the schema path, document path, and
vector of messages from the validator. The display implementation joins
these messages for CLI diagnostics.

## Data and control flow

`validate` reads and parses the schema, then reads and parses the document.
It passes both values and paths to `validate_value`. That entrypoint builds
a fresh `jsonschema` validator on each call. A successful `is_valid` returns
immediately; otherwise `iter_errors` supplies the violation messages.

The schema path has operational meaning even for in-memory inputs.
`schema_base_uri` derives a file URI from a nonempty parent directory.
`schema_registry_root` searches that path's ancestors for `spec/schemas`;
when absent it uses the immediate parent as the retrieval root.
A synthetic path without a parent selects the library's default retrieval
behavior, suitable for a self-contained inline schema.

Chio HTTPS references map into that root using the URI path. When the
mapped file is absent, the retriever scans local JSON files for a matching
`$id`, accepting equality after trimming trailing slashes. Relative file
references use the derived base URI.

## Trust and invariants

With a nonempty schema parent, `LocalSchemaRetriever` accepts local `file`
references and the two Chio HTTPS namespaces, `chio.world/schemas/` and
`chio-protocol.dev/schemas/`. HTTP and unregistered HTTPS references return
errors. Other URI schemes are rejected.

`join_schema_path` rejects parent traversal in Chio URI paths.
`read_local_schema_file` canonicalizes the requested file and retrieval root,
then requires the file to remain beneath the canonical root. This checks
symlink escapes before reading the referenced schema. The initial schema
and instance paths themselves are read directly by `load_json`.

`load_json` reads the complete file before parsing; there is no byte budget
at this layer. `serde_json::Value` parsing supplies instance values without
a duplicate-field or canonical-number rejection pass. A document's own
`$ref` field is data unless its schema assigns it special constraints.

## Dependencies

`serde_json` supplies the parsed values and file decoding. `jsonschema`
compiles schemas and evaluates instances. The workspace dependency disables
default features and enables file resolution, so the default configuration
also lacks HTTP retrieval. The custom retriever maps published Chio identifiers
to repository-local schemas.

## Verification

`cargo test -p chio-spec-validate` runs unit tests for network refusal,
sibling-file references, absolute Chio `$id` resolution, and references outside
the root. Artifact tests check nested anchor payloads, supported signature
envelope shapes, checkpoint version rules, hashes, and log-ID spelling.

The `scenarios`, `fiscal`, `bound_tool_invocation`, and `ws2_protocol_ladder`
integration suites exercise repository schemas and document mutations.
Their schema assertions describe accepted shapes; signature-shaped strings
in those fixtures receive no cryptographic verification here.

See the [README](README.md) for the inline API example and the
[serialization contract](../../../spec/PROTOCOL.md#4-serialization-and-identity)
for signed-artifact requirements.
