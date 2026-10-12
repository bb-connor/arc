# chio-lsp

`chio-lsp` provides editor diagnostics, completion, hover, and definition
navigation for Chio configuration documents. Its binary speaks LSP over
stdio; its library exposes the same providers for embedding and testing.
The shared document cache supplies text to each request handler.

## Usage

Run the configuration diagnostic provider without starting an editor or server:

```rust
use chio_lsp::diagnostics::chio_yaml::validate;

let valid = "version: 1\npolicy: ./policy.yaml\n";
assert!(validate(valid).is_empty());

let missing_policy = validate("version: 1\n");
assert_eq!(missing_policy.len(), 1);
assert!(missing_policy[0].message.contains("policy"));
```

The `chio-lsp` executable takes LSP messages on stdin and sends responses on
stdout. Clients should use full document synchronization, which
`ChioLanguageServer::capabilities()` advertises alongside completion,
hover, and definition support.

## Guarantees

- `DocumentLanguage::detect` recognizes Chio language IDs before checking
  filename suffixes. Unrecognized documents receive no diagnostics.
- `diagnostics::chio_yaml::validate` requires a YAML mapping with `version`
  and `policy` keys. Values and referenced policy files are outside this check.
- `diagnostics::manifest::validate` checks a `tools` sequence of mappings
  with an `id` key. The runtime manifest loader enforces the full manifest contract.
- `diagnostics::guard_dsl::validate` requires a `guards` sequence whose
  entries contain string IDs beginning with `urn:chio:guard:`.
- `definition` restricts linked manifest reads to recognized filenames
  within the document directory after canonicalization.

## Status

This workspace package has a library and a stdio binary and is marked
`publish = false`. Diagnostics are structural YAML checks. Completion uses
static catalogs and is implemented for `chio.yaml`; hover recognizes scope,
guard, and registered error URNs across the three supported document languages.
Definition navigation follows scope and guard URNs. Kernel admission, policy
evaluation, signature verification, and manifest authorization belong to
runtime components.

Lifecycle and provider integration tests run with `cargo test -p chio-lsp`.
The `diagnostic_latency` benchmark measures cold-start and repeated diagnostic
calls against a synthesized configuration document.

## Related

- [Architecture](ARCHITECTURE.md)
- [Manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract)
- [Schema validator](../chio-spec-validate/README.md)
- [Error registry](../../core/chio-errors/README.md)
- [Editor integrations](../../../integrations/editors/)

## License

[Apache-2.0](../../../LICENSE)
