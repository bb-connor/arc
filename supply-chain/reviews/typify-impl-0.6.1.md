# typify-impl 0.6.1 source review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for source identity and the demonstrated generation boundaries. This is direct
source review, not independent human certification or full JSON Schema
conformance certification.

Registry archive SHA-256:
`a2fd0d27608a466d063d23b97cf2d26c25d838f01b4f7d5ff406a7446f16b6e3`.
Release: oxidecomputer/typify commit
`f65c6dd14317605f4f25a076d99ba4c4f41f0d15`, directory `typify-impl`.

## Scope and behavior

Reviewed both manifests and all 14 production modules: public settings and
type registry, schema conversion, merging, cycle handling, enum and struct
recognition, token generation, defaults, value emission, schema substitutions,
Rust type extensions, identifier helpers and limited value validation. Also
reviewed the test comparison harness, three integration cases, fixture
inventory and upstream documentation.

This is a pure Rust generator with no unsafe code, build script, network
client, filesystem access or subprocess execution in production source.
Diagnostics can print schemas to logging/stdout. The test harness invokes
rustfmt and reads fixture files. Output uses quoted string literals for data
and documentation, sanitized identifiers for schema names, and parsed Rust
paths/tokens for explicitly supplied code-generation settings. Those settings
have source-code authority and are trusted inputs.

Chio selects 0.6.1 through nono 0.53.0's build script. That script processes
its packaged capability-manifest schema with default settings and struct
builders, then writes Rust to Cargo's output directory. Chio's specification
generator separately uses 0.4.3. The owned confinement adapter constructs
capabilities directly and does not call nono's generated-manifest parser or
manifest conversion API.

## Limits that callers must retain

- Generated types do not enforce the whole input schema. General numeric
  ranges and `multipleOf`, `const`, boolean enumerations, variable array size,
  uniqueness and parts of object/subschema constraints are not fully
  preserved. The upstream README explicitly describes bounded-number limits.
  The emitted representation for sets is currently a vector.
- A runtime test confirms that a type generated for ports in 1..65535 accepts
  65536; another confirms ignored constant, uniqueness and array-size
  constraints. These tests record limitations, not successful validation.
  The actual packaged nono schema also accepts a different well-formed
  version and an out-of-range nonzero port during deserialization. Nono's
  separately inspected `CapabilitySet::try_from` uses checked `u16::try_from`
  for every connect/bind/localhost port and rejects overflow. No such
  manifest conversion is selected by Chio's owned adapter.
- String constraints without a known format generate private newtypes and
  checked parsing/deserialization. Runtime length checks count characters;
  the generator's enum-filter helper counts UTF-8 bytes. Known formats and
  schema-combination heuristics can discard other restrictions. Generated
  types must not be the sole authorization or schema-validation boundary.
- Unsupported or malformed schemas can panic, and reference/merge recursion
  and expansion have no global work budget. External references fail rather
  than fetching their targets. Recursive Rust containment is handled by
  inserted boxes, but that is not a general hostile-schema resource limit.
- Conversion mutates a type registry before some errors. Discard a registry
  after failed generation. Reused sanitized names may select a prior type
  without proving structural equality. Internal ordering also intentionally
  ignores some schema/default details; it is not semantic equivalence.
- Defaults and explicitly substituted native types can emit conversion
  `unwrap`s. A compiled generated type is not proof that every possible
  default or replacement meets application requirements.
- Unknown Rust extensions default to normal generation. `UnknownPolicy::Deny`
  also falls back to generation in the reviewed helper; it does not implement
  the advertised hard rejection. A retained test confirms this behavior.

These limits require reviewed schemas and separate application validation.
They do not create a new authority path in the selected Chio adapter. Treating
arbitrary schemas as runtime policy would require additional engineering.

## Validation and conclusion

All 103 upstream unit tests and three integration tests pass without changing
source, golden output or assertions. Four documentation checks pass; two are
explicitly ignored upstream. The three integration cases compare generated
Rust for ordinary types, GitHub and Vega fixtures. The facade's separate
suite also compiles 21 distinct generated fixtures. Strict all-target,
all-feature Clippy passes for the unchanged backend.

Five added tests exercise generated string/enum/required-field/unknown-field
and builder rejection, ignored schema constraints, the exact nono schema,
invalid pattern/default rejection, external-reference rejection and the
unknown-crate fallback. The generated runtime uses regress 0.11.1, matching
nono's selected runtime dependency; typify-impl itself uses regress 0.10.5.

The nono schema was extracted from its checksum-verified registry archive
(`ae7eb523cc2036e9ad6527411c3da5dc2172dc454cc3447a03b910420a39bfee`),
with schema SHA-256
`e1fddcf56f6a15bca68952811182b26c80114c2af50a510c3aa60b8fd9ccf54d`.
The retained boundary Rust file expects that schema as
`nono-capability.schema.json` and its companion schema as
`boundaries.schema.json` at the test package root.

The package receives a `safe-to-deploy` source audit as a generator for
reviewed build inputs with these limits. This does not certify nono, regress,
all possible generated code or the full workspace qualification.

Evidence is retained in the primary checkout under
`output/process-security-20260915/typify-audit-a19274a53/`. The standalone
qualification workspace preserves all original package files and uses a
separate lock seeded from Chio; the boundary test package is separate again.
