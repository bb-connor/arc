# chio-lsp architecture

## Responsibility and boundary

The library exports `ChioLanguageServer`, `ServerCapabilitiesSnapshot`,
`DocumentCache`, `DocumentEntry`, and `DocumentLanguage`. Public provider
modules also allow direct diagnostics, completion, hover, and definition calls.
The binary calls `server::run_stdio` on a Tokio runtime.

The server owns opened document text and editor protocol handling. Diagnostics
parse YAML and check selected structural fields. Runtime policy loading,
manifest signature verification, guard execution, and tool dispatch remain
outside this boundary. A clean editor diagnostic result carries only the
checks implemented by the selected provider.

## Structure

| Module | Responsibility |
| --- | --- |
| `server` | LSP lifecycle, capabilities, document events, provider dispatch |
| `document` | Shared `DashMap` cache, versions, language detection |
| `diagnostics` | Configuration, manifest, and guard DSL structural checks |
| `completion` | Static scope, guard, and configuration-key catalogs |
| `hover` | URN lookup in catalogs and the error registry |
| `definition` | URN extraction and scoped manifest lookup |
| `position` | Conversion between UTF-16 columns and UTF-8 byte offsets |

Each cache entry holds its text in `Arc<String>`. Cloning `DocumentCache`
shares its map, allowing the server and test harness to inspect the same
opened document state. Replacing an unknown URI returns `None` and does
not insert a new document.

## Data and control flow

Opening a document classifies its language and caches the text and version,
then publishes diagnostics with that version. Recognized language IDs take
precedence over suffix detection. Change handling takes the first incoming
content change as the full replacement body. Closing removes the entry and
publishes an empty diagnostic list.

Completion uses the current line prefix and nearest top-level section header.
For `chio.yaml`, scope-like sections select scope items, `guards` selects
guard items, and other positions offer configuration keys. Manifest and guard
DSL documents return an empty completion list.

Hover extracts the URN at the cursor and returns Markdown help from
`chio-errors` or the scope and guard catalogs. Definition requests accept
scope and guard URNs, try the document's top-level `manifest:` pointer, and
fall back to the first matching occurrence in the opened text.

## Trust and invariants

Configuration diagnostics require `version` and `policy` key presence.
Manifest diagnostics require a sequence of tool mappings with `id` keys;
an empty sequence and an arbitrary ID value pass these structural checks.
Guard diagnostics require string IDs with the guard URN prefix. These
providers do not load JSON Schema files or authenticate the document.

`diagnostic_with_urn` maps parser locations from one-based positions to
zero-based, zero-width LSP ranges. Cursor providers convert UTF-16 columns
before slicing UTF-8 strings and convert returned ranges back to UTF-16.

The definition resolver rejects absolute paths, parent components, and
unrecognized manifest filenames. It canonicalizes the document directory
and target, requiring the target to remain within that directory before
reading it. A rejected or unreadable linked file permits an in-document
fallback. File reads have no size limit in this resolver.

## Dependencies

`tower-lsp` supplies protocol types, client publication, and stdio serving;
Tokio supplies asynchronous I/O. `dashmap` stores shared document entries.
`yaml_serde` parses the diagnostic inputs. `chio-errors` provides registered
error descriptions for hover responses.

## Verification

`cargo test -p chio-lsp` runs lifecycle tests and separate integration suites
for all diagnostic providers, completion, hover, and definition navigation.
Resolver tests exercise absolute-path refusal, parent traversal, filename
restrictions, and same-directory links. Position and hover tests include
multibyte text and UTF-16 ranges.

`cargo bench -p chio-lsp --bench diagnostic_latency` measures provider calls;
it does not benchmark kernel dispatch or editor transport latency.

See the [README](README.md) for an in-memory diagnostic example and the
[manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract) for the
runtime document requirements.
