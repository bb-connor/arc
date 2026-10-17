# chio-verdict-matrix-driver-lambda

A Lambda deployment-shape client for the Chio verdict matrix. It loads the
shared scenario corpus, sends supported cases to an operator-supplied Chio
sidecar, and compares `(verdict, reason_code, scope_set)` tuples.
It exercises only that sidecar. It does not run or test the detect-only
`chio-lambda-extension`, and its matrix results make no claim about it.

## Usage

Extract a tuple from an evaluation response without contacting a sidecar.
The helper reads response fields; this example uses a local JSON fixture.

```rust
use chio_verdict_matrix_driver_lambda::tuple_from_evaluate_response;
use serde_json::json;

let response = json!({
    "verdict": { "verdict": "deny", "reason": "urn:chio:error:capability:revoked" },
    "receipt": { "metadata": {} }
});
let tuple = tuple_from_evaluate_response(&response).normalized();
assert_eq!(tuple.verdict, "deny");
assert_eq!(tuple.reason_code, "urn:chio:error:capability:revoked");
assert!(tuple.scope_set.is_empty());
```

`run_driver(root, sidecar_url)` loads the corpus and produces a `DriverReport`.
The binary finds the corpus by walking upward from its working directory and
prints the report as JSON. It reads `CHIO_VERDICT_MATRIX_SIDECAR_URL`, falling
back to `CHIO_SIDECAR_URL`. Neither variable is needed for the example above.
This package declares no Cargo features.

## Guarantees

`load_scenarios` rejects symlinked roots and encountered symlinks, parses JSON,
and checks `chio.verdict-matrix.scenario.v1`. `run_driver` reports every case as
`unsupported` without a nonempty sidecar URL. Capability and revocation cases
remain unsupported because the relay cannot construct signed tokens.

Attempted requests have a five-second timeout. Transport errors, unsuccessful
HTTP statuses, malformed JSON responses, and tuple mismatches produce `fail`.
`VerdictTuple::normalized` sorts scopes and preserves duplicates.
The binary exits 2 for setup errors, 1 for failed cases, and 0 otherwise;
a zero exit can therefore represent an entirely unsupported corpus.

## Status

Test transport client with publication disabled. It builds synthetic request
metadata and unsigned capability headers. Tuple extraction reads receipt
metadata without checking a receipt signature. The registry smoke test checks
driver registration and file presence. A real sidecar run, Lambda invocation,
and runtime security acceptance need their own execution evidence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Conformance crate](../../../README.md)
- [Matrix manifest](../../manifest.toml)
- [Lambda extension](../../../../../../sdks/lambda/chio-lambda-extension/README.md)
- [Protocol evidence boundary](../../../../../../spec/PROTOCOL.md#54-safety-properties-and-evidence-boundary)
- [Kubernetes driver](../k8s/README.md)

Licensed under [Apache-2.0](../../../../../../LICENSE).
