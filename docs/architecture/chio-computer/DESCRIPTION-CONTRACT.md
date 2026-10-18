# Computer description contract

`chio-runtime-core::computer` describes an immutable resource basis.
`chio-runtime-core::program` checks and compiles ordered program expressions.
Python exposes the same contract through `chio.computer`; TypeScript exports it
from `@chio-protocol/sdk`.

These APIs perform no filesystem, network, process, model, signing or authority
operation. A checked description grants no execution rights. Native WORK
lowering, current owner admission, protected parent-input construction and
serving-owner refusal require the CT-WORK preparation and submission contract.

## Records

Every wire object has a closed field set. Fields are required, including
`parentRevision`, whose root value is explicitly `null`. Content references
contain an owner domain, artifact identity, lowercase SHA-256 digest and declared
byte length. A content reference cannot authorize lookup or an arbitrary fetch.
Resource identities and owners remain distinct even when their bytes match.

| Record | Binding |
|---|---|
| `ComputerRecord` | Computer and owner, optional parent revision, exact head, lifecycle generation and profile references |
| `ComputerRevision` | Computer and owner, revision digest, namespace digest, boot/input references, input shape, exact resources/profiles and creation operation |
| `ResourceBinding` | Canonical namespace, resource and owner, binding generation, provider, operation set, pinned content or explicit live mode |
| `ComputerImage` | Exact revision, boot/input references, resource-manifest digest and a subset of declared profiles |

The namespace digest commits to the ordered resource bindings. The revision
digest commits to every revision field except `revisionId`. The digest constructor
accepts an empty `revisionId` placeholder or a valid digest; complete descriptions
require a valid digest. The image and record
must identify that revision and its exact boot, input, namespace and profiles.
These checks describe a supplied basis; they do not establish a current catalog,
receiver approval, live-resource version, revocation state or lifecycle fence.

Task leaves describe a contract, input/output schemas, protected acceptance
reference, harness requirements and resource requirements. The receiver retains
harness selection and admission. Program leaves describe a pinned bundle,
entrypoint, schemas and resource requirements. Bundle resolution, code admission
and qualified confinement remain receiver responsibilities.

## Composition and identities

Rust and Python use `&` for parallel composition and `|` for sequence. Thus
`a & b & c | d | e` has the same description as the TypeScript form
`parallel(a, b, c).pipe(d).pipe(e)`.

Normalization flattens associative parallel and sequence nodes without changing
order or removing leaves. Every parallel branch receives the same immutable
input shape. A sequence passes its preceding stage's output shape to its next
stage. Schema references must match exactly; the compiler performs no schema
conversion or result verification. The supported join shape is an ordered
all-success list. It describes dataflow, not accepted results or the WORK
parent-input artifact manifest.

Each leaf has a distinct canonical occurrence path. Occurrence identity binds
the retained request ID, owner, Computer, revision, program digest and path.
Repeated leaves remain separate. An exact retry reproduces their identities;
a new request produces different identities. Detection of changed material
under an already retained request ID belongs to its durable owner.

Hash input is canonical JSON for `{"domain": domain, "body": value}`:

| Domain | Body |
|---|---|
| `chio.computer.namespace.v1` | Ordered resource bindings |
| `chio.computer.revision.v1` | Revision fields excluding `revisionId` |
| `chio.computer.program.v1` | Normalized expression |
| `chio.computer.occurrence.v1` | Request, owner, Computer, revision, program digest and path |
| `chio.computer.compiled.v1` | Compiled-description fields excluding `digest` |

SDK parsing helpers return bounded untrusted JSON values; compilation validates
closed fields and record relationships. Rust `ComputerDescription::from_json`
also validates its typed record. Compiled descriptions remain untrusted.
`validate_compiled_program` and
`validateCompiledProgram` bound the supplied description, independently compile
the expected input and compare the complete result. Rust's `CheckedProgram`
has private construction and no deserialization implementation. Neither the
checked value nor the wire DTO can construct a native session or capability.

## Limits and refusal

| Dimension | Maximum |
|---|---:|
| Source JSON and aggregate typed compilation input | 2 MiB |
| Compiled JSON | 8 MiB |
| JSON number token | 1,024 ASCII bytes |
| JSON depth | 96 |
| Source collection entries, including object fields | 65,536 |
| Compiled collection entries, including object fields | 262,144 |
| Individual JSON string or object key | 1,024 UTF-8 bytes |
| Opaque identifier | 128 ASCII bytes |
| Canonical namespace | 256 bytes |
| Resource bindings or requirements per record/leaf | 256 |
| Profiles per list | 64 |
| Aggregate declared content-reference bytes | 64 MiB |
| Expression depth / nodes / leaves | 32 / 2,047 / 1,024 |
| Dependency edges / all-success parents | 4,096 / 16 |
| Generation | 1 through 9,007,199,254,740,991 |

Expression and record limits apply before program normalization, deep cloning or hashing. The bounded JSON reader checks original depth and exact numbers before duplicate-aware decoding, then checks decoded collection and string budgets before typed projection. Typed
input also receives a bounded serialization pass before compilation. A stricter
semantic limit takes precedence. Collection-entry limits also bound decoded node
counts, because each non-root JSON value occupies an entry.

Numeric fields contain nonnegative safe integers. Exact integral JSON spellings
such as `1.0`, `1e0` and `10e-1` normalize to `1`; negative zero normalizes to
zero. Fractional values, precision-losing spellings, out-of-range integers and
overlong numeric tokens refuse with `json_number`. Original duplicate keys and
malformed Unicode refuse with `json_shape`. The normalized JSON also fits the
applicable byte limit.

Opaque IDs use ASCII letters, digits, `.`, `_` and `-`, starting with a letter
or digit. Namespace segments use the same grammar; empty, `.` and `..` segments
are refused. References have no URL, filesystem path, credential, environment,
key-store or authority-store field. Read, write and invoke are the only resource
operations, with no duplicates. Requirements must match resource identity,
owner and generation and request only declared operations.

Rejections expose a fixed rule code without echoing untrusted values. Examples
include `json_shape`, `wire_bytes`, `expression_depth`, `resource_subset`,
`input_schema`, `revision_binding` and `compiled_mismatch`.

## Schemas and vectors

The unsigned contracts are
[description.schema.json](../../../spec/schemas/chio-computer/v1/description.schema.json)
and [compiled-description.schema.json](../../../spec/schemas/chio-computer/v1/compiled-description.schema.json).
JSON Schema validates closed wire shape; compiler checks additionally enforce
aggregate limits, reference relationships, dataflow, digests and exact equality.
These standalone schemas are outside native wire codegen and the signed-artifact
registry.

[Shared vectors](../../../tests/bindings/vectors/computer/v1.json) pin canonical
bytes, both leaf kinds, real operator precedence, occurrence paths, retry/new
request identities and exact refusals. Native dispatch, receiver admission,
durable lifecycle operations and serving-owner refusal are separate acceptance
boundaries described in [the acceptance contract](ACCEPTANCE.md).
